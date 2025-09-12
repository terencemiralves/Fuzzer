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


### TODO

- [X] Move extract_tokens and pattern notion to `dispatcher.py`.
- [X] Parse config for `string_bug.py` or put all in `dispatcher.py` and remove parsing in `bof_exploit.py`.
- [X] Documentation.
- [X] For example :
    - `python3 src/main.py --mode binary --binary ./target/bof/ch33` -> ask 2 times to setup type binary and type input.