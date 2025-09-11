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
    def __init__(self, binary_path, type_binary=None, type_input=None, verbose=False):
        """
        Initialize the BinaryClient with the binary path and type.
        :param binary_path: Path to the binary file
        :param type_binary: Type of binary:
                    - "i" for interactive (while True loop)
                    - "ni" for non-interactive (send a command and the process exits)
        :param type_input: Type of input:
                    - "i" for standard input (stdin)
                    - "f" for file as arg (file is passed as an argument to the binary)
                    - "arg" for argument (binary is run with exploitable arguments)
        :param verbose: If True, enable verbose logging
        """
        # Declarations
        self.binary_path = binary_path
        self.verbose = verbose
        self.elf = None
        self.p = None

        if self.verbose:
            context.log_level = 'debug'
        else:
            context.log_level = 'error'
        
        # Type of binary: "i" for interactive, "ni" for non-interactive
        self.type_binary = type_binary
        # Type of input: "stdin" for stdin, "f" for file as arg, "arg" for argument, "a" for automatic
        self.type_input = type_input

        if self.type_binary is None or self.type_input is None:
            self.setup_type(type_binary, type_input)

        # Check if the binary path is set
        if not self.binary_path:
            raise ValueError("Binary path is not set.")
        # Check if the binary file exists
        if not os.path.isfile(self.binary_path):
            raise FileNotFoundError(f"Binary file not found: {self.binary_path}")
        # Check if the type_input and type_binary are valid
        if self.type_input not in ["stdin", "f", "arg"]:
            raise ValueError("Invalid type_input. Must be 'stdin', 'f', or 'arg'.")
        # Check if the type_binary is valid
        if self.type_binary not in ["i", "ni"]:
            raise ValueError("Invalid type_binary. Must be 'i' or 'ni'.")

    def setup_type(self, type_binary=None, type_input=None):
        """
        Setup the type of binary and input based on the binary path.
        This method is called after the binary client is initialized.
        """
        if type_binary:
            self.type_binary = type_binary
        else:
            print("There are 2 types of binary: 'i' for interactive (while True loop) and 'ni' for non-interactive (send a command and the process exits).")
            input_str = input("Enter the type of binary (i/ni): ").strip().lower()
            if input_str in ["i", "ni"]:
                self.type_binary = input_str
            else:
                raise ValueError("Invalid type_binary. Must be 'i' or 'ni'.")
        if type_input:
            self.type_input = type_input
        else:
            print("There are 3 types of input: 'stdin' for standard input (stdin), 'f' for file as arg (file is passed as an argument to the binary) and 'arg' for argument (binary is run with exploitable arguments).")
            input_str = input("Enter the type of input (stdin/f/arg): ").strip().lower()
            if input_str in ["stdin", "f", "arg"]:
                self.type_input = input_str
            else:
                raise ValueError("Invalid type_input. Must be 'stdin', 'f', or 'arg'.")
        
        
    ### CHECKS ###

    def process_alive(self):
        """
        Check if the binary process is alive.
        """
        if self.p is not None:
            return self.p.poll() is None
        return False
    
    def is_connected(self):
        """
        Check if the client is connected.
        :return: True if connected, False otherwise
        """
        return self.p is not None and self.p.connected()
    

    def is_interactive(self):
        """
        Check if the client is interactive.
        :return: True if interactive, False otherwise
        """
        return self.type_binary == "i"
    
    
    ### CONNECTIONS ###

    def connect(self):
        """
        Connect to the binary process.
        """
        
        self.elf = ELF(self.binary_path)
        if self.type_input != "f" and self.type_input != "arg":
            self.p = process(self.binary_path)
        else:
            if self.verbose:
                print("[!] Binary is the type 'f' or 'arg' so no need to connect.")
        if self.verbose:
            print(f"Connected to binary: {self.binary_path}")

    ### SEGFAULTS ###

    def get_address_segfault(self, command):
        """
        Get the core file path
        :param command: Command to send to the binary process
        :return: The address of the segmentation fault
        Note: Enable verbose to see all the core dumps and the address of the segmentation fault.
        """
        core_pattern = "/proc/sys/kernel/core_pattern"
        if os.path.exists(core_pattern):
            with open(core_pattern, 'r') as f:
                if f.read().strip() != "core":
                    print("[!] Core pattern is not set to 'core'.")
                    raise RuntimeError("Core pattern is not set to 'core'.")
        else:
            raise FileNotFoundError("Core pattern file not found.")
        pwd = os.getcwd()
        with enable_core_dumps("/tmp"):
            if self.type_input == "stdin":
                p = Popen([pwd + "/" + self.binary_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                p.stdin.write(command + b"\n")
                p.stdin.flush()
            elif self.type_input == "f":
                f = open(TMP_EXPLOIT_FILE, "wb")
                f.write(command)
                f.close()
                if self.verbose:
                    print("Process is a file, sending command as argument.")
                p = Popen([pwd + "/" + self.binary_path, TMP_EXPLOIT_FILE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/tmp")
            elif self.type_input == "arg":
                p = Popen([pwd + "/" + self.binary_path, command], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            ret = p.wait()
            if self.type_input == "f":
                os.remove(TMP_EXPLOIT_FILE)
            if ret == 0:
                if self.verbose:
                    print(f"[-] No segmentation fault detected for size {len(command)}.")
                return None

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

    ### REQUESTS AND RESPONSES ###

    def send_request(self, command):
        """ Send a command to the binary process and return the return code. Return None if the process is still alive."""
        # Binary with stdin input
        if self.type_input == "stdin":
            # Interactive binary
            if self.type_binary == "i":
                if self.verbose:
                    print("Process is interactive, sending command as input.")
                if self.process_alive():
                    self.p.sendline(command)
                else:
                    raise RuntimeError("Process is not alive, cannot send command.")
            # Non-interactive binary
            elif self.type_binary == "ni":
                if self.verbose:
                    print("Process is non-interactive, sending command as input.")
                if self.process_alive():
                    self.p.sendline(command)
                else:
                    raise RuntimeError("Process is not alive, cannot send command.")
        # Binary with file as input
        elif self.type_input == "f":
            ### Never see a interactive binary with a file as input, so this is not implemented
            f = open(TMP_EXPLOIT_FILE, "wb")
            f.write(command)
            f.close()
            if self.verbose:
                print("Process is a file, sending command as argument.")
            self.p = process([self.binary_path, TMP_EXPLOIT_FILE])
        # Binary with argument input
        elif self.type_input == "arg":
            if self.verbose:
                print("Process is an argument, sending command as argument.")
            self.p = process([self.binary_path, command])
        
        # Check if the process is alive
        if not self.process_alive():
            if self.verbose:
                print("Process is not alive, returning return code.")
            if self.type_input == "f":
                os.remove(TMP_EXPLOIT_FILE)
            return self.p.returncode
        else:
            if self.verbose:
                print("Process is still alive")
            if self.type_binary == "ni":
                self.p.wait()
                if self.type_input == "f":
                    os.remove(TMP_EXPLOIT_FILE)
                return self.p.returncode
            else:
                return None

        

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
        if self.type_binary == "ni":
            self.p.close()
        return response
    
    def interactive(self):
        """
        Start an interactive session with the binary process.
        :return: None
        """
        if self.p is None:
            print("Connection not established. Call connect() first.")
            return
        if self.verbose:
            print("Starting interactive session with the binary process.")
        self.p.interactive()

    def close(self):
        if self.verbose:
            print("Closing binary client connection.")
        if self.p:
            self.p.close()
        if self.verbose:
            print("Connection closed.")