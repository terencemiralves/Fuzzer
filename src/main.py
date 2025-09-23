import argparse
import yaml
from exploit.exploit import Exploit
from printer import print_colored, print_success, print_error, print_info

def load_config(path):
    if (not path.endswith('.yml')) and (not path.endswith('.yaml')):
        print_error("[!] Config file must be a .yml or .yaml file")
        exit(1)
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
            print_colored("[!] Missing arguments mode\nRetry with --mode <binary|web|ssh>", 'red')
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

    print_colored(f"[+] Mode : {config['mode']}", 'green')
    if config["mode"] == "binary":
        print_colored(f"  → Binary : {config['binary']}", 'cyan')
    elif config["mode"] == "web":
        print_colored(f"  → URL : {config['url']}:{config['port']}", 'cyan')
    elif config["mode"] == "ssh":
        print_colored(f"  → SSH : {config['ssh']['user']}@{config['ssh']['host']} (password: {config['ssh']['password']})", 'cyan')

    print_colored(f"[+] Trying to find buffer overflow...", 'cyan')

    exploit = Exploit(config)
    bof_index = exploit.run_bof_exploit()
    if bof_index == -1:
        print_colored("[-] No buffer overflow detected", 'red')
    else:
        print_colored(f"[+] Buffer overflow detected with size: {bof_index}", 'green')

    print_colored(f"[+] Trying string bug format", 'cyan')

    string_bug = exploit.run_string_bug_exploit()

    print_colored("[+] Fuzzing completed.", 'green')

if __name__ == "__main__":
    main()
