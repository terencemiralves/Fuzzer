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