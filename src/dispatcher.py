
from connection.ssh_client import SSHClient
from connection.web_client import WebClient
from connection.binary_client import BinaryClient

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
                verbose=self.config.get("verbose", False)
            )
            
        else:
            raise ValueError("Unsupported mode: {}".format(self.config["mode"]))
        
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
        
    def receive_response(self):
        if self.client:
            return self.client.receive_response()
        else:
            raise ValueError("Client not initialized")
        
    def close(self):
        if self.client:
            self.client.close()
        else:
            raise ValueError("Client not initialized")