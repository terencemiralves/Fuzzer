# backend/main.py
import os
import shutil
import stat
import uuid
import shlex
import asyncio
from typing import Dict, Any
from fastapi import FastAPI, UploadFile, File, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import logging
from fastapi import Form
import yaml

class QuotedStringDumper(yaml.SafeDumper):
    def represent_str(self, data):
        # Always use double quotes for strings
        return self.represent_scalar('tag:yaml.org,2002:str', data, style='"')

QuotedStringDumper.add_representer(str, QuotedStringDumper.represent_str)


APP_ROOT = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(APP_ROOT, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


# Template command used to run the fuzzer; must include {target}
# Example default: run "python3 ./fuzzer.py {target}"
# You can override with environment variable FUZZER_CMD_TEMPLATE
FUZZER_CMD_TEMPLATE = os.environ.get("FUZZER_CMD_TEMPLATE", "python3 /app/src/main.py --mode binary --binary {target} --config {config}")

app = FastAPI()
app.mount("/static", StaticFiles(directory=os.path.join(APP_ROOT, "static")), name="static")

# In-memory run store. For a small local app this is sufficient.
# run_id -> {
#   "proc": asyncio.subprocess.Process,
#   "queue": asyncio.Queue,  # lines to send to websocket(s)
#   "status": "running"|"finished"|"error",
#   "tasks": [asyncio.Task, ...]
# }
RUNS: Dict[str, Dict[str, Any]] = {}

@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    logger = logging.getLogger("uvicorn")

    # Generate unique filename to avoid conflicts
    unique_name = f"{uuid.uuid4()}-{file.filename}"
    dest_path = os.path.join(UPLOAD_DIR, unique_name)

    # Save the uploaded file
    try:
        with open(dest_path, "wb") as f:
            shutil.copyfileobj(file.file, f)

        # ✅ Make the file executable for user/group/others
        os.chmod(dest_path, os.stat(dest_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        logger.info("Uploaded file saved and made executable: %s", dest_path)
        return {"ok": True, "filename": unique_name, "path": dest_path}

    except Exception as e:
        logger.error("Failed to upload file: %s", e)
        return {"ok": False, "error": str(e)}


@app.post("/start_scan")
async def start_scan(
    filename: str = Form(...),
    verbose: bool = Form(False),
    timeout: int = Form(300),
):
    """
    Start a scan run.
    - filename: name returned from /upload (not full path)
    - verbose: whether to add verbose arg (frontend provides)
    - timeout: maximum runtime in seconds (server will kill after)
    """
    logger = logging.getLogger("uvicorn")
    logger.info("start_scan called with filename=%s verbose=%s timeout=%s", filename, verbose, timeout)

    host_path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(host_path):
        raise HTTPException(status_code=404, detail="uploaded file not found")

    # Create a run id early so config filename can use it
    run_id = str(uuid.uuid4())

    # --- Build a small YAML config dict (expand this as UI grows) ---
    config_dict = {
        "verbose": bool(verbose),
        "mode": "binary",
        # the fuzzer config expects a path to the binary; we give the saved server path
        "binary": host_path,
        # sensible defaults; you can add UI controls later to override these
        "process_interactive": False,
        "type_input": "stdin",
        "sendline": True
    }

    # write config file next to uploaded file, named with the run id
    config_filename = f"run-{run_id}.yml"
    logger.info("Opening file %s", config_filename)
    config_path = os.path.join(UPLOAD_DIR, config_filename)
    try:
        with open(config_path, "w", encoding="utf-8") as cf:
            yaml.dump(
                config_dict,
                cf,
                default_flow_style=False,
                sort_keys=False,
                Dumper=QuotedStringDumper
            )
    except Exception as e:
        logger.info("Opening file %s FAILED", config_filename)
        logger.info(e)
        raise HTTPException(status_code=500, detail=f"Failed to write config file: {e}")

    # --- Build the command to run the fuzzer ---
    cmd_template = FUZZER_CMD_TEMPLATE
    print("Parsing CMD")
    if "{target}" not in cmd_template and "{config}" not in cmd_template:
        print("Didn't find {target} or {config} in the template")
        # allow template without placeholders: append the target and config
        # default behaviour: append target and --config <path> if not present
        filled = cmd_template
        args = shlex.split(filled)
        # append target if it makes sense (if target not already passed in the template)
        # We'll append the target path as last positional argument
        args.append(host_path)
        # Append config flag if template didn't contain {config}
        args.extend(["--config", config_path])
    else:
        print("Found target, building cmd")
        # If template contains placeholders, substitute accordingly
        filled = cmd_template.replace("{target}", shlex.quote(host_path)).replace("{config}", shlex.quote(config_path))
        print("CMP= " + filled)
        print(cmd_template)
        args = shlex.split(filled)
        print(args)

    # If user requested verbose and the template didn't already include a verbose flag,
    # we add a common --verbose flag. You can adjust this logic to your fuzzer's CLI.
    if verbose and not any(a in ("-v", "--verbose") for a in args):
        args.append("--verbose")

    # Create queue + run record before launching
    q: asyncio.Queue = asyncio.Queue()
    RUNS[run_id] = {"proc": None, "queue": q, "status": "starting", "tasks": [], "config": config_filename}

    async def run_and_stream():
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            RUNS[run_id]["proc"] = proc
            RUNS[run_id]["status"] = "running"

            async def read_stream(stream, tag):
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    text = line.decode(errors="replace")
                    await q.put(f"{tag}:{text}")
                return

            t1 = asyncio.create_task(read_stream(proc.stdout, "OUT"))
            t2 = asyncio.create_task(read_stream(proc.stderr, "ERR"))
            RUNS[run_id]["tasks"].extend([t1, t2])

            async def killer():
                await asyncio.sleep(timeout)
                if proc.returncode is None:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    await q.put("SYSTEM:Process killed after timeout\n")

            kt = asyncio.create_task(killer())
            RUNS[run_id]["tasks"].append(kt)

            await proc.wait()
            await t1
            await t2

            await q.put(f"SYSTEM:Process exited with code {proc.returncode}\n")
            RUNS[run_id]["status"] = "finished"
        except Exception as e:
            RUNS[run_id]["status"] = "error"
            await q.put(f"SYSTEM:Runner error: {e}\n")
        finally:
            await q.put(None)

    task = asyncio.create_task(run_and_stream())
    RUNS[run_id]["tasks"].append(task)

    # Return run_id and generated config filename so frontend can show it
    return {"run_id": run_id, "config": config_filename}


@app.websocket("/ws/logs/{run_id}")
async def ws_logs(ws: WebSocket, run_id: str):
    await ws.accept()
    meta = RUNS.get(run_id)
    if not meta:
        await ws.send_text("SYSTEM:run not found\n")
        await ws.close()
        return

    q: asyncio.Queue = meta["queue"]

    try:
        while True:
            item = await q.get()
            if item is None:
                # end of stream
                await ws.send_text("SYSTEM:STREAM_END\n")
                await ws.close()
                break
            # send item as-is
            await ws.send_text(item)
    except WebSocketDisconnect:
        # client disconnected; we keep the process running
        pass
    except Exception:
        try:
            await ws.send_text("SYSTEM:stream error\n")
            await ws.close()
        except Exception:
            pass


@app.get("/")
async def index():
    # return the static front-end index
    p = os.path.join(APP_ROOT, "static", "front/index.html")
    with open(p, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())

