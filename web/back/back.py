# backend/main.py
import os
import uuid
import shlex
import asyncio
from typing import Dict, Any
from fastapi import FastAPI, UploadFile, File, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(APP_ROOT, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Template command used to run the fuzzer; must include {target}
# Example default: run "python3 ./fuzzer.py {target}"
# You can override with environment variable FUZZER_CMD_TEMPLATE
FUZZER_CMD_TEMPLATE = os.environ.get("FUZZER_CMD_TEMPLATE", "python3 ../../src/main.py {target}")

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
    # Save uploaded file into UPLOAD_DIR with safe filename
    unique = str(uuid.uuid4())
    filename = f"{unique}-{file.filename}"
    path = os.path.join(UPLOAD_DIR, filename)
    with open(path, "wb") as f:
        data = await file.read()
        f.write(data)
    # make non-executable by default; user can choose to upload executable with its mode
    try:
        os.chmod(path, 0o644)
    except Exception:
        pass
    return {"ok": True, "filename": filename, "path": path}


@app.post("/start_scan")
async def start_scan(filename: str, verbose: bool = False, timeout: int = 300):
    """
    Start a scan run.
    - filename: name returned from /upload (not full path)
    - verbose: whether to add verbose arg (frontend provides)
    - timeout: maximum runtime in seconds (server will kill after)
    """
    host_path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(host_path):
        raise HTTPException(status_code=404, detail="uploaded file not found")

    # Build the command
    # Replace {target} in template with quoted path
    # Use shlex.split for proper argument splitting
    cmd_template = FUZZER_CMD_TEMPLATE
    if "{target}" not in cmd_template:
        raise HTTPException(status_code=500, detail="FUZZER_CMD_TEMPLATE must contain {target}")

    filled = cmd_template.replace("{target}", shlex.quote(host_path))
    args = shlex.split(filled)

    # If user requested verbose, append a common verbose flag if needed.
    # NOTE: change this if your fuzzer expects another flag.
    if verbose:
        args.append("--verbose")

    run_id = str(uuid.uuid4())
    q: asyncio.Queue = asyncio.Queue()
    RUNS[run_id] = {"proc": None, "queue": q, "status": "starting", "tasks": []}

    async def run_and_stream():
        try:
            # start the subprocess
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
                    # prefix to help frontend decide style
                    await q.put(f"{tag}:{text}")
                return

            t1 = asyncio.create_task(read_stream(proc.stdout, "OUT"))
            t2 = asyncio.create_task(read_stream(proc.stderr, "ERR"))
            RUNS[run_id]["tasks"].extend([t1, t2])

            # also schedule a timeout killer
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

            # wait for process to finish
            await proc.wait()
            # ensure readers finish
            await t1
            await t2

            await q.put(f"SYSTEM:Process exited with code {proc.returncode}\n")
            RUNS[run_id]["status"] = "finished"
        except Exception as e:
            RUNS[run_id]["status"] = "error"
            await q.put(f"SYSTEM:Runner error: {e}\n")
        finally:
            # sentinel to indicate stream end
            await q.put(None)

    task = asyncio.create_task(run_and_stream())
    RUNS[run_id]["tasks"].append(task)

    return {"run_id": run_id}


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

