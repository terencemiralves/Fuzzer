# Fuzzer
Fuzzer for find overflow / string bug / ...


```bash
ulimit -c unlimited
cat /proc/sys/kernel/core_pattern
core
```

## Tests
 
Run the tests with:

```bash
python3 tests/testsuite.py
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

## Launch tests suite

```bash
python3 tests/testsuite.py 
```

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

### Binary mode options

- `binary` : path to the target binary.
    > Used only in binary mode for this moment.
- `type_binary` : type of binary execution. Options are:
    - `ni` : not interactive, will ask for input and close the program.
    - `i` : interaction (not implemented yet), will keep the program running for multiple inputs.
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
    - `check at {ignore} : {address}` -> will ignore the first token and extract the second one as address.
    > Used only in string bug exploit for this moment.

### Options for buffer overflow exploit

- `send_payload_template` : template for sending payloads. For example:
    - `USERNAME=__PAYLOAD__` -> will send `USERNAME=` + payload.
    > Used only in bof exploit for this moment.

### TODO

- [X] Move extract_tokens and pattern notion to `dispatcher.py`.
- [X] Parse config for `string_bug.py` or put all in `dispatcher.py` and remove parsing in `bof_exploit.py`.
- [X] Documentation.
- [X] For example :
    - `python3 src/main.py --mode binary --binary ./target/bof/ch33` -> ask 2 times to setup type binary and type input.
- [X] Test on x86_64.
- [X] Test web and ssh mode.
- [X] Verbose mode in stringbug.
- [X] Add ROP blind method in bof_exploit.