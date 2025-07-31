from glob import glob
from multiprocessing import context, process
from subprocess import Popen
from tools.enable_core_dump import enable_core_dumps
from pwn import *
import subprocess
import glob
import os

PARSE_ERROR_FOR_FILE = [b"Usage", b"help"]
TMP_EXPLOIT_FILE = "/tmp/exploit_file"

class BinaryClient:
    def __init__(self, binary_path, payload_in_argv=False, verbose=False):
        # Declarations
        self.binary_path = binary_path
        self.verbose = verbose
        self.elf = None
        self.p = None
        if self.verbose:
            context.log_level = 'debug'
        else:
            context.log_level = 'error'
        
        # Type of binary: "i" for interactive, "ni" for non-interactive or "f" for file as arg
        self.type = None

        # Check
        if not self.binary_path:
            raise ValueError("Binary path is not set.")

        # Initialization
        if payload_in_argv:
            self.type = "f"
        else:
            self.find_type_of_binary()
        

    def find_type_of_binary(self):
        self.connect()
        if not self.process_alive():
            response = self.receive_response()
            if self.verbose:
                print("[!] Binary is not alive, response:", response)
            if response and any(error in response for error in PARSE_ERROR_FOR_FILE):
                self.type = "f"
                self.close()
                if self.verbose:
                    print("Binary is a file, not an interactive binary.")
                return

        self.send_request(b"test")
        self.receive_response()
        if self.p.poll() is None:
            self.type = "i"
            self.close()
            if self.verbose:
                print("Binary is interactive.")
  
        else:
            self.type = "ni"
            if self.verbose:
                print("Binary is non-interactive.")

    def process_alive(self):
        if self.p is not None:
            return self.p.poll() is None
        return False
    
    def is_connected(self):
        """
        Check if the client is connected.
        :return: True if connected, False otherwise
        """
        return self.p is not None and self.p.connected()
    
    def connect(self):
        if not os.path.isfile(self.binary_path):
            raise FileNotFoundError(f"Binary file not found: {self.binary_path}")
        self.elf = ELF(self.binary_path)
        if self.type != "f":
            self.p = process(self.binary_path)
        if self.verbose:
            print(f"Connected to binary: {self.binary_path}")

    def get_address_segfault(self, command):
        """ Get the core file path """
        core_pattern = "/proc/sys/kernel/core_pattern"
        if os.path.exists(core_pattern):
            with open(core_pattern, 'r') as f:
                if f.read().strip() != "core":
                    print("[!] Core pattern is not set to 'core'.")
                    raise RuntimeError("Core pattern is not set to 'core'.")
        else:
            raise FileNotFoundError("Core pattern file not found.")
        with enable_core_dumps("/tmp"):
            if self.type == "ni":
                p = Popen(["/media/ugopc/UGO/Fuzzer/" + self.binary_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                p.stdin.write(command + b"\n")
                p.stdin.flush()
                p.wait()

                core_files = glob.glob("/tmp/core*")
                if not core_files:
                    raise RuntimeError("Aucun core dump trouvé dans /tmp.")
                else:
                    if self.verbose:
                        print("[+] Core dump trouvé :", core_files[0])

                    core = Coredump(core_files[0])

                    os.remove(core_files[0])

                    return hex(core.fault_addr)
        return None    


    def send_request(self, command):
        """ Send a command to the binary process and return the """
        # Check if the process is alive and of the correct type
        if self.type == "i" and self.process_alive() or self.type == "ni" and self.process_alive():
            self.p.sendline(command)

        # If the process is interactive and not alive, reconnect
        elif self.type == "ni" and not self.process_alive():
            if self.verbose:
                print("Process is not alive, reconnecting...")
            self.connect()
            self.p.sendline(command)

        # Initialization of the type
        elif self.type == None:
            self.p.sendline(command)
        elif self.type == "f":
            f = open(TMP_EXPLOIT_FILE, "wb")
            f.write(command)
            f.close()
            if self.verbose:
                print("Process is a file, sending command as argument.")
            self.p = process([self.binary_path, TMP_EXPLOIT_FILE])
            os.remove(TMP_EXPLOIT_FILE)
            
        else:
            raise RuntimeError("Process is not alive or not connected.")
        
        if self.type == 'ni':
            self.p.wait()
            return self.p.poll()

        if self.verbose:
            print(f"Sent command: {command}")

    def receive_response(self, arg=4096):
        """
        Receive a response from the binary process
        :param arg: Number of bytes to receive, default is 4096 or 'line' to receive until a newline or a specific string to receive until
        :type arg: int or str
        :return: The response received from the binary process
        """
        if type(arg) == int:
            response = self.p.recv(arg)
        elif type(arg) == str and arg == 'line':
            response = self.p.recvline()
        elif type(arg) == str:
            response = self.p.recvuntil(arg.encode())
        else:
            raise ValueError("Argument must be an integer or a string ('line' or any other string to recvuntil).")
        return response
    
    def close(self):
        if self.verbose:
            print("Closing binary client connection.")
        if self.p:
            self.p.close()
        if self.verbose:
            print("Connection closed.")