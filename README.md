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


-> Faire en sorte d'essayer sans \n et avec \n si timeout