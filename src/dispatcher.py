
from connection.ssh_client import SSHClient
from connection.web_client import WebClient
from connection.binary_client_clean import BinaryClient

class Dispatcher:
    def __init__(self, config):
        self.config = config
        self.client = None
        if self.config["mode"] == "ssh":
            self.client = SSHClient(
                self.config["ssh"]["host"],
                self.config["ssh"].get("port", 22),
                self.config["ssh"]["user"],
                self.config["ssh"].get("password", None),
                verbose=self.config.get("verbose", False)
            )
        elif self.config["mode"] == "web":
            self.client = WebClient(
                self.config["url"],
                self.config["port"],
                verbose=self.config.get("verbose", False)
            )
        elif self.config["mode"] == "binary":
            self.client = BinaryClient(
                self.config["binary"],
                self.config.get("type_binary", None),
                self.config.get("type_input", None),
                verbose=self.config.get("verbose", False)
            )
            
        else:
            raise ValueError("Unsupported mode: {}".format(self.config["mode"]))
        
    def is_connected(self):
        """
        Check if the client is connected.
        :return: True if connected, False otherwise
        """
        if self.client:
            return self.client.is_connected()
        else:
            raise ValueError("Client not initialized")
        
    def is_interactive(self):
        """
        Check if the client is interactive.
        :return: True if interactive, False otherwise
        """
        if self.client:
            return self.client.is_interactive()
        else:
            raise ValueError("Client not initialized")

    def connect(self):
        if self.client:
            self.client.connect()
        else:
            raise ValueError("Client not initialized")
        
    def get_segfault(self, command):
        if self.client and hasattr(self.client, 'get_address_segfault'):
            return self.client.get_address_segfault(command)
        else:
            raise ValueError("Client does not support segfault retrieval or is not initialized")
        
    def send_command(self, command):
        if self.client:
            return self.client.send_request(command)
        else:
            raise ValueError("Client not initialized")
        
    def receive_response(self, arg=4096):
        """
        Receive a response from the target service.
        :param arg: Number of bytes to receive, default is 4096 or 'line' to receive until a newline or a specific string to receive until
        :type arg: int or str
        :return: The response received from the target service
        """
        if self.client:
            return self.client.receive_response(arg)
        else:
            raise ValueError("Client not initialized")
        
    def close(self):
        if self.client:
            self.client.close()
        else:
            raise ValueError("Client not initialized")
        
    def parse_instructions(self, instructions):
        """
        Send the initial instructions to the target service.
        :param instructions: List of instructions to execute, this list should contain tuples of (command, argument)
                             Commands can be "recv" or "send". Careful with the command "recv" for recv an int you should give an integer and not a string.
        :return: None
        """
        if instructions and self.is_connected():
            for command, arg in instructions:
                if self.client.verbose:
                    print(f"Executing command: {command} with arg: {arg}")
                if command == "recv":
                    response = self.receive_response(arg)
                    if self.client.verbose:
                        print(f"Received: {response}")
                elif command == "send":
                    if isinstance(arg, str):
                        arg = arg.encode()
                    elif not isinstance(arg, bytes):
                        raise ValueError("Argument must be a string or bytes")
                    if self.client.verbose:
                        print(f"Sending: {arg}")
                    self.send_command(arg)
                else:
                    raise ValueError(f"Unknown command: {command}")
        else:
            raise ValueError("Instructions not set up or client not connected. Call setup_init_instructions() or connect() first.")
        
    def interactive(self):
        """
        Start an interactive session with the target service.
        :return: None
        """
        if self.client:
            self.client.interactive()
        else:
            raise ValueError("Client not initialized")