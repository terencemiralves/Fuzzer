import argparse
import yaml
from bof_exploit import OverflowExploit
def load_config(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)

def main():

    parser = argparse.ArgumentParser(description="Fuzzer for Binary, Web, and SSH modes")
    parser.add_argument("--mode", choices=["binary", "web", "ssh"], help="Working mode")
    parser.add_argument("--binary", help="Binary to load")
    parser.add_argument("--url", help="Target URL")
    parser.add_argument("--port", type=int, help="Target port")
    parser.add_argument("--ssh-user", help="SSH user")
    parser.add_argument("--ssh-host", help="SSH host")
    parser.add_argument("--ssh-password", help="SSH password")
    parser.add_argument("--config", help="Path to another config file", default="")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    # Override the config with CLI args if specified
    if args.config:
        config = load_config(args.config)
    else:
        if args.mode == "ssh":
            config = load_config("config/ssh_config.yml")
            if args.verbose:
                print("[!] Using SSH default config")
        elif args.mode == "web":
            config = load_config("config/web_config.yml")
            if args.verbose:
                print("[!] Using Web default config")
        elif args.mode == "binary":
            config = load_config("config/binary_config.yml")
            if args.verbose:
                print("[!] Using Binary default config")
        else:
            print("[!] Missing arguments mode\nRetry with --mode <binary|web|ssh>")
            return
    config["binary"] = args.binary or config.get("binary")
    config["url"] = args.url or config.get("url")
    config["port"] = args.port or config.get("port")
    config["ssh"] = config.get("ssh", {})
    if args.ssh_user:
        config["ssh"]["user"] = args.ssh_user
    if args.ssh_host:
        config["ssh"]["host"] = args.ssh_host
    if args.ssh_password:
        config["ssh"]["password"] = args.ssh_password

    config["verbose"] = args.verbose or config.get("verbose", False)

    print(f"[+] Mode : {config['mode']}")
    if config["mode"] == "binary":
        print(f"  → Binary : {config['binary']}")
    elif config["mode"] == "web":
        print(f"  → URL : {config['url']}:{config['port']}")
    elif config["mode"] == "ssh":
        print(f"  → SSH : {config['ssh']['user']}@{config['ssh']['host']} (password: {config['ssh']['password']})")
    
    print(f"[+] Trying to find buffer overflow...")

    bof_exploit = OverflowExploit(config)
    bof_index = bof_exploit.run()
    if not bof_index:
        print("[-] No buffer overflow detected")
    else:
        print(f"[+] Buffer overflow detected with size: {bof_index}")

    print(f"[+] Trying string bug format")


    print("[+] Fuzzing completed.")

if __name__ == "__main__":
    main()
