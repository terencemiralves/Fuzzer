
import socket

class WebClient:
    def __init__(self, url, port, verbose=False):
        self.url = url
        self.port = port
        self.verbose = verbose
        self.s = None
        if self.verbose:
            print(f"WebClient initialized with URL: {self.url} and port: {self.port}")

    def connect(self):
        if self.verbose:
            print(f"Connecting to {self.url}:{self.port}")
        try:
            self.s = socket.create_connection((self.url, self.port))
            if self.verbose:
                print(f"Connected to {self.url}:{self.port}")
        except socket.error as e:
            print(f"Failed to connect to {self.url}:{self.port} - {e}")
            self.s = None

    def send_request(self, request):
        if self.s is None:
            print("Connection not established. Call connect() first.")
            return
        if self.verbose:
            print(f"Sending request: {request}")
        self.s.sendall(request.encode())
        if self.verbose:
            print("Request sent.")

    def receive_response(self):
        if self.s is None:
            print("Connection not established. Call connect() first.")
            return
        response = self.s.recv(4096)
        if self.verbose:
            print(f"Received response: {response.decode()}")
        return response.decode()
    
    def close(self):
        if self.s:
            if self.verbose:
                print("Closing web client connection.")
            self.s.close()
            if self.verbose:
                print("Connection closed.")
        else:
            if self.verbose:
                print("No connection to close.")
        self.s = None