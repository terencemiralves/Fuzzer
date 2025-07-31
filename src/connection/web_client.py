
from pwn import *

class WebClient:
    def __init__(self, url, port, verbose=False):
        self.url = url
        self.port = port
        self.verbose = verbose
        self.p = None
        if self.verbose:
            print(f"WebClient initialized with URL: {self.url} and port: {self.port}")
        else:
            context.log_level = 'error'

    def connect(self, timeout=5):
        if self.verbose:
            print(f"Connecting to {self.url}:{self.port}")
        try:
            self.p = remote(self.url, self.port)
            self.p.settimeout(timeout)
            if self.verbose:
                print(f"Connected to {self.url}:{self.port}")
        except Exception as e:
            if self.verbose:
                print(f"Failed to connect to {self.url}:{self.port} - {e}")
            self.p = None

    def is_connected(self):
        """
        Check if the client is connected.
        :return: True if connected, False otherwise
        """
        return self.p is not None and self.p.connected()

    def send_request(self, request):
        if self.p is None:
            print("Connection not established. Call connect() first.")
            return
        if self.verbose:
            print(f"Sending request: {request}")
        self.p.send(request)
        if self.verbose:
            print("Request sent.")

    def receive_response(self, arg=4096):
        """
        Receive a response from the binary process
        :param arg: Number of bytes to receive, default is 4096 or 'line' to receive until a newline or a specific string to receive until
        :type arg: int or str
        :return: The response received from the binary process
        """
        if self.p is None:
            print("Connection not established. Call connect() first.")
            return
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
        if self.p is not None:
            if self.verbose:
                print("Closing web client connection.")
            self.p.close()
            if self.verbose:
                print("Connection closed.")
        else:
            if self.verbose:
                print("No connection to close.")
        self.p = None