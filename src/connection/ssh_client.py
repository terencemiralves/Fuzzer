import paramiko

class SSHClient:
    def __init__(self, hostname, port, username, password, verbose=False):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.verbose = verbose

    def connect(self):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.hostname, self.port, self.username, self.password)
            if self.verbose:
                print(f"Connected to {self.hostname} on port {self.port} as {self.username}")
            return client
        except paramiko.SSHException as e:
            print(f"Failed to connect to {self.hostname}:{self.port} - {e}")
            return None
    def close(self, client):
        if self.verbose:
            print(f"Closing connection to {self.hostname}")
        client.close()

    def send_request(self, client, command):
        if self.verbose:
            print(f"Executing command: {command}")
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode()
        errors = stderr.read().decode()
        if self.verbose and output:
            print(f"Output: {output}")
        if self.verbose and errors:
            print(f"Errors: {errors}")
        return output, errors

    def receive_response(self, client):
        if self.verbose:
            print("Receiving response")
        stdin, stdout, stderr = client.exec_command('echo "Response from server"')
        response = stdout.read().decode()
        if self.verbose:
            print(f"Received response: {response}")
        return response

    def close(self):
        if hasattr(self, 'client') and self.client:
            self.close(self.client)
        else:
            if self.verbose:
                print("No active SSH connection to close.")
        self.client = None