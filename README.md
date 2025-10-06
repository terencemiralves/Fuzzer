# CTF Fuzzer
Fuzzer for find **overflow**, **format string bug** in CTF challenge. More features will be added in the future.

## Requirements

For binary mode, we need to set core dump and core pattern to `core` in order to detect crashes and get the EIP/RIP value.

```bash
ulimit -c unlimited
cat /proc/sys/kernel/core_pattern
core
```

## How to use

### Arguments

1. `--mode` : choose the type of connection for the target program. Options are:
    - `binary` : for local binary execution (working in progress).
    - `ssh` : for remote execution via SSH (not implemented yet).
    - `web` : for web-based targets (not implemented yet).
2. `--binary` : path to the target binary (required for `binary` mode).
3. `--url` : URL of the web target (required for `web` mode).
4. `port` : port number for the web target (default is 80).
5. `--ssh-user` : SSH username (required for `ssh` mode).
6. `--ssh-host` : SSH hostname or IP address (required for `ssh` mode).
7. `--config` : path to the configuration file (check in the directory `config/`).
    - Default config for `binary` mode: `config/binary_config.yml`.
    - Default config for `web` mode: `config/web_config.yml`.
    - Default config for `ssh` mode: `config/ssh_config.yml`.

8. `--verbose` : enable verbose output for debugging purposes.

### Example commands

#### Binary mode

Find overflow in a binary:

```bash
python3 src/main.py --mode binary --binary ./target/bof/ch15 --config config/binary_config.yml --verbose
```
And send `ni` and `stdin`.

Exploit string bug in a binary:

```bash
python3 src/main.py --mode binary --binary ./target/string_bug/ch14 --config config/bin_ch14_conf.yml --verbose
```

Exploit string bug in a binary and try to find flag format:

```bash
python3 src/main.py --mode binary --binary ./target/string_bug/custom_read_stack --config config/bin_c_read_stack.yml
```

## Environment variables

Set `COLOR=1` in the `.env` file to enable colored terminal output. Any other value will disable colors.

## Config files

Config files are in the `config/` directory. You can create your own config file based on the examples provided.

There are many available options in the config files.

### Common options

For general cases, you can use the following options:
- `verbose` : enable verbose output for debugging purposes.
- `arch` : architecture of the target binary (e.g., "x86", "x86_64").
    > Not working for this moment.
- `mode` : mode of operation. Options are:
    - `binary` : for local binary execution.
    - `ssh` : for remote execution via SSH (not implemented yet).
    - `web` : for web-based targets (not implemented yet).
    > Used in all modes for this moment.
- `process_interactive` : boolean for type of interaction with the process. Options are:
    - `true` : non-interactive mode, the program only ask for input once.
    - `false` : interactive mode, the program can ask for input multiple times.

- `send_payload_template` : template for sending payloads. For example:
    - `USERNAME=__PAYLOAD__` -> will send `USERNAME=` + payload.

- `receive_payload_template` : template for extracting information from received payloads. For example:
    - `Welcome user at address __EXTRACT__` -> will extract the address from the response.

### Binary mode options

- `binary` : path to the target binary.
    > Used only in binary mode for this moment.
    > Used only in binary mode for this moment.
- `type_input` : type of input method. Options are:
    - `arg` : input via command line argument.
    - `stdin` : input via standard input.
    - `file` : input via file, give the file path to the program as argument.
    > Used only in binary mode for this moment.
- `ASLR` : enable or disable ASLR (Address Space Layout Randomization) for the target binary.
    > Used only in binary mode for this moment.
- `expected_responses` : list of expected responses from the target program to determine if the program crashed or not.
    > Used only in binary mode for this moment.
- `sendline` : whether to use `sendline` (True) or `send` (False) when sending input to the target program.
    > Used only in binary mode for this moment.


### Options for format string bug exploit

- `init_instructions` : -> check if it's working (string bug exploit). For example:
    - `[("send", "toto"), ("recv", 4096)]` -> will send `toto` and receive 4096 bytes as initial instructions before starting the exploit.
    > Used only in string bug exploit for this moment.

- `pattern_payload` : pattern to extract address for get the offset of string bug format. For example:
    - `check at {__IGNORE__} : {__EXTRACT__}` -> will ignore the first token and extract the second one as address.
    > Used only in string bug exploit for this moment.

### Options for buffer overflow exploit

- `send_payload_template` : template for sending payloads. For example:
    - `USERNAME=__PAYLOAD__` -> will send `USERNAME=` + payload.
    > Used only in bof exploit for this moment.

## Launch tests suite

```bash
python3 tests/testsuite.py 
```

### TODO

- [X] Setup correctly the delay and remove from string bug.
- [X] Move interactive process to dispatcher.
- [X] Move extract_tokens and pattern notion to `dispatcher.py`.
- [X] Make exploit modular (string bug / bof / ...).
- [X] Documentation.
- [X] For example :
    - `python3 src/main.py --mode binary --binary ./target/bof/ch33` -> ask 2 times to setup type binary and type input.
- [X] Test on x86_64.
- [X] Test web and ssh mode.
- [X] Verbose mode in stringbug.
- [X] Add ROP blind method in bof_exploit.
- [X] Need to do a version that without any arguments just fuzz the binary with default config.
- [X] Need to optimize the code.
- [X] Need to optimize performance.
- [X] Print string stack to find FLAG with a template like `FLAG{__EXTRACT__}`. https://github.com/majerugo/Rootme/tree/main/app_system/elf_x86_format_string_bug_basic_1 => if ASLR disabled or infinite loop with brute force.
- [X] Env variable address and try to use it if the stack is executable. https://github.com/majerugo/Rootme/tree/main/app_system/elf_x86_format_string_bug_basic_3 => if stack is executable and (ASLR disabled or infinite loop with brute force).
- [X] Thanks to the stack base brute force to find our payload address with -> ```payload = p32(starting_address) + b"%__offset__$s\n"``` -> `p32(starting_address) + p32(starting_address) + b'%__offset__$s'` in response https://github.com/majerugo/Rootme/tree/main/app_system/elf_x86_remote_format_string_bug => if stack is executable and (ASLR disabled or infinite loop with brute force).
- [X] Brute force with the .text base address to find a instruction that change our EIP/RIP. https://github.com/majerugo/Rootme/tree/main/app_system/elf_x86_remote_format_string_bug => if PIE disabled or infinite loop with brute force.

## Sources

- [PwntoolsProcess](https://docs.pwntools.com/en/stable/tubes/processes.html)
