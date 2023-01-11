# Trabalho realizado na Semana #12 e #13


---

## CTF

### Challenge 1

Initially we ran the provided code <kbd>nc ctf-fsi.fe.up.pt 6000 </kbd> in the shell and got an encrypted sequence of numbers and letters.

![](https://i.imgur.com/EhOQIBI.png)

By analyzing the provided python code we realized that it would be necessary to calculate the prime number greater than 2^512 and 2^513. For this we also used a python code that returned this number.

```
import random

def isMillerRabinPassed(mrc):
    maxDivisionsByTwo = 0
    ec = mrc-1
    while ec % 2 == 0:
        ec >>= 1
        maxDivisionsByTwo += 1
    assert(2**maxDivisionsByTwo * ec == mrc-1)
 
    def trialComposite(round_tester):
        if pow(round_tester, ec, mrc) == 1:
            return False
        for i in range(maxDivisionsByTwo):
            if pow(round_tester, 2**i * ec, mrc) == mrc-1:
                return False
        return True
 
    numberOfRabinTrials = 20
    for i in range(numberOfRabinTrials):
        round_tester = random.randrange(2, mrc)
        if trialComposite(round_tester):
            return False
    return True
 
def nextPrime(N):
 
    if (N <= 1):
        return 2
 
    prime = N
    found = False
 
    while(not found):
        prime = prime + 1
 
        if(isMillerRabinPassed(prime) == True):
            found = True
 
    return prime
 
N = 2**512 #or 2**513
print(nextPrime(N))
```

So all that remains is to find out the value of d. To do this, we used a python algorithm, found online. 
```
def mod_inverse(x,y):
	def eea(a,b):
		if b==0:return (1,0)
		(q,r) = (a//b,a%b)
		(s,t) = eea(b,r)
		return (t, s-(q*t) )

	inv = eea(x,y)[0]
	if inv < 1: inv += y #we only want positive values
    return inv
```

We replaced all the values in the executable we were given:


```
from binascii import hexlify, unhexlify

p = 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171
q = 26815615859885194199148049996411692254958731641184786755447122887443528060147093953603748596333806855380063716372972101707507765623893139892867298012168351
n = p*q
e = 0x10001 # a constant
d = 32148745104617719611469860837520069095243013547461161624365705436392549353428328854051450263424947795515997965956157657970803482741943111508623685194329747704158900209679524603520884720244523165529357010257764632981617985618265704337977264403534764689557688026111797495540714181081554773530395510587656455823


enc_flag = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a13c3a7d1822d00d9617a232699a375997f57ee94321d7bab3774816baad0b7a832cee9941e2a8f5e0b002aeda7364cf6cc3476d1995a9226d8518c39ab89a731ca0ca6cffbf1b98f5e67c9803fa85ac10c56121a62638e0a6e241648c6a3a1ebe1da88895be365c173aff3ad421dcc1798edd9be9953ec4a91a8a1fbcd35e72"

def enc(x):
    int_x = int.from_bytes(x, "big")
    y = pow(int_x,e,n)
    return hexlify(y.to_bytes(256, 'big'))

def dec(y):
    int_y = int.from_bytes(unhexlify(y), "big")
    x = pow(int_y,d,n)
    return x.to_bytes(256, 'big')

y = dec(enc_flag)
print(y.decode())
```

Finally, we ran the code and find the flag.

![](https://i.imgur.com/zHDUodO.png)


flag:
```
flag{901f3ab61335e9f64f3cfe6147a8d2c4}
```


### Challenge 2

As with the previous CTF, we start by running the provided code <kbd>nc ctf-fsi.fe.up.pt 6001</kbd> in the shell and we had three encrypted values, N (which was the same for both messages) and two different values of E.

![](https://i.imgur.com/9vViFdQ.png)

To do this we used some python code, found online, and replaced it with the values we got from the shell.
```
import gmpy2
   
class RSAModuli:
    def __init__(self):
       self.a = 0
       self.b = 0
       self.m = 0
       self.i = 0
    def gcd(self, num1, num2):
       if num1 < num2:
           num1, num2 = num2, num1
       while num2 != 0:
           num1, num2 = num2, num1 % num2
       return num1
    def extended_euclidean(self, e1, e2):
       self.a = gmpy2.invert(e1, e2)
       self.b = (float(self.gcd(e1, e2)-(self.a*e1)))/float(e2)
    def modular_inverse(self, c1, c2, N):
       i = gmpy2.invert(c2, N)
       mx = pow(c1, self.a, N)
       my = pow(i, int(-self.b), N)
       self.m= mx * my % N
    def print_value(self):
       print("Plain Text: ", self.m)
   
   
def main():
   c = RSAModuli()
   N = 29802384007335836114060790946940172263849688074203847205679161119246740969024691447256543750864846273960708438254311566283952628484424015493681621963467820718118574987867439608763479491101507201581057223558989005313208698460317488564288291082719699829753178633499407801126495589784600255076069467634364857018709745459288982060955372620312140134052685549203294828798700414465539743217609556452039466944664983781342587551185679334642222972770876019643835909446132146455764152958176465019970075319062952372134839912555603753959250424342115581031979523075376134933803222122260987279941806379954414425556495125737356327411
   c1 = 0x9d331ad71ee40f619840a2a92f1287307d0070bbc0e860cf8f5ee7d3b167749b989e9dd326f6837c74206ddaaa655f94aa0fdb2391cc9f8d5d69db0521a9148e4efe1121a0fb2acff146a8318d17695a2953fe4661bac9698d71396a1586824277925ae495576666ccfe5b93ddf270f917f02e8a6855a19797cc95fbb6a702c14d4b6c40bd18935ff25322ce1302ccf902bd2227ebdbe809d208bb5c09988cc7b51cf30aa429b11d0cb1bcbbce8b5ff88feea57f3a32415e755881ff55ce41f38465290e09dbea2a1bb8cbd801018772caaf1426bd2c8708cdd2b6cf9c67bda8a818721de5b7f561b1ee37e8161a5d794e966296c82aad997e92fa7e625f630d
   c2 = 0xbdb92c72b74448c305b8b45acaa76e0897a0c8296956b15ca30752a649c0ffe6453f33eef4e01770fdfde4519c24e68daf8c2d85d0439202f728acab8560ce1d9c67161c1580189c94548769997cca81486379db3a693a22ca1325cc1cf2093cae5a821439b9af60d61a866cf4f360187ec31bf6991259f247ee9d6b538b3bd6efaaa668d06fbbc75c8176aac02b68d5021f94e61b1e17e33117bf585bdad1fea496f68e5ad487c310c692a98745ebc80defab42f9845b6db1d4f429dfbf5ad4aec60d90f40ceb011a65aa6bba942e1ddb89155e0c7cedb05982da28b8bd09107d05b022a2e430c3ad91b3b51af608e82391f650031b3411f6f1aa54dc6bc39c
   e1 = 65537
   e2 = 65539
   c.extended_euclidean(e1, e2)
   c.modular_inverse(c1, c2, N)
   c.print_value()

if __name__ == '__main__':
   main()
```

After running the code we got the output of the function, the Plain Text in decimal:

![](https://i.imgur.com/TXjVjZn.png)

First we converted the Plain Text (in decimal) to hexadecimal.

![](https://i.imgur.com/ErOben8.png)

Finally, we convert from hexadecimal to text (using the ASCII table) and find the flag.

![](https://i.imgur.com/SDKhqNw.png)


flag:
```
flag{986037b8a0f76edbd349a9e777477f11}
```


## Public-Key Infrastructure (PKI) Lab

### Task 1

We want to become a Certificate Authority (CA) so that we can issue a digital certificate for others. 

In this task we firstly need to copy openssl.cnf into our PKI folder so we can have the configuration file to create certificates. After this, under `[CA Default]` section the following content needs to be present:

```
dir = ./demoCA
certs = $dir/certs
crl_dir = $dir/crl
database = $dir/index.txt
unique_subject = no # <- uncommented
new_certs_dir = $dir/newcerts
serial = $dir/serial
```
We then needed to create the <kbd>demoCA</kbd> folder and add the necessary files according to the requirements in the lab pdf:

```
mkdir demoCA
cd demoCA
mkdir certs crl newcerts
touch index.txt
echo "1000" > serial
```

After the initial setup, we need to generate a self-signed certificate for our CA:

![](https://i.imgur.com/5bpvdXy.png)

We can use the following commands to look at the decoded content of the X509 certificate and the RSA key:

Output of <kbd>openssl x509 -in ca.crt -text -noout</kbd>:

```
[12/11/22]seed@VM:~/.../PKI$ openssl x509 -in ca.crt -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            28:c1:1d:6f:d6:09:f2:1b:d9:8d:cc:f8:34:86:4c:7a:72:8d:9f:6e
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN = www.modelCA.com, O = Model CA LTD., C = US
        Validity
            Not Before: Dec 11 16:46:41 2022 GMT
            Not After : Dec  8 16:46:41 2032 GMT
        Subject: CN = www.modelCA.com, O = Model CA LTD., C = US
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (4096 bit)
                Modulus:
                    00:a9:31:28:b5:1b:a1:f2:06:8b:4a:b4:50:32:7a:
                    1f:9f:77:2e:35:71:46:0a:09:03:01:25:bf:39:e1:
                    25:94:c6:60:6d:5e:28:37:7d:b4:71:74:81:f3:6f:
                    89:53:86:83:00:8f:5c:25:96:c7:0f:d9:fd:3a:50:
                    77:ff:9a:13:4a:77:65:a3:8e:ae:e3:fd:04:99:9b:
                    82:a7:43:aa:39:21:f0:d5:23:e2:3a:b7:46:c3:2c:
                    86:e9:c5:d8:ee:6d:d5:98:07:0b:fa:bf:be:d8:c0:
                    a0:cc:e3:96:1e:85:f2:bf:41:28:d8:37:90:91:be:
                    76:c3:7a:ad:6a:fa:76:7e:28:32:e4:77:4c:63:d1:
                    e4:13:5d:71:2c:4d:77:f8:1f:cb:f5:3b:88:3a:67:
                    05:eb:50:16:a4:b9:81:50:d3:6a:1c:a6:66:7b:cb:
                    46:d4:da:51:02:33:6e:f8:75:50:9a:6a:18:6c:7a:
                    9b:20:a3:99:d0:d2:c3:5e:62:a2:c5:51:e5:08:b7:
                    c8:2a:b4:99:e8:1c:b3:62:49:ee:2a:e5:d9:f1:86:
                    53:5b:2a:90:33:6b:39:48:c3:76:7b:45:ea:a5:03:
                    1c:77:51:3a:4f:86:6d:51:3d:f2:fc:b7:cd:1a:40:
                    c9:59:25:4b:25:29:d0:ae:ab:12:61:63:5b:4c:d1:
                    01:68:35:0a:21:de:50:4e:43:c2:8b:06:d3:87:94:
                    87:5d:c6:8b:d5:97:19:79:4c:80:34:d3:46:4b:bd:
                    2d:4e:32:cb:ad:79:03:e9:b1:d0:5e:f8:90:d8:0c:
                    43:65:22:74:b2:d1:45:db:63:4b:a1:5d:cc:45:16:
                    cd:16:81:86:a8:c0:0b:33:0f:91:28:97:79:b2:14:
                    58:d3:1c:bb:b1:80:b0:5a:da:57:cf:3d:a3:c0:24:
                    d1:9f:17:8d:6d:eb:4b:38:e0:e4:c3:69:2b:32:77:
                    98:fc:53:06:6b:99:6c:57:f2:5f:e5:98:bb:ae:54:
                    b7:4a:3b:7c:d6:41:ee:c1:40:3d:44:53:a9:f9:ee:
                    23:97:11:c2:ca:9c:64:6c:6b:85:73:97:4e:27:72:
                    af:1f:c0:08:61:47:e8:8a:3c:ea:d9:95:95:6c:c9:
                    89:54:9b:e8:15:55:19:65:ac:a0:cd:b9:34:91:44:
                    ab:f6:31:5f:9c:14:bc:dd:e5:73:4c:ef:5f:f3:f2:
                    35:3e:d6:79:79:d2:7f:05:e8:11:42:45:90:28:f2:
                    f8:63:56:0b:1e:58:10:c6:7e:8e:4a:e0:2a:86:d6:
                    ec:c4:cd:da:c9:41:e2:1c:fe:e5:d2:55:9f:01:05:
                    be:f2:2e:11:98:da:ff:82:ce:03:ed:c8:7a:0f:fb:
                    de:99:59
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                3B:EB:06:9D:23:95:1C:4E:2F:74:51:B5:63:06:8B:F9:C2:8A:46:DC
            X509v3 Authority Key Identifier: 
                keyid:3B:EB:06:9D:23:95:1C:4E:2F:74:51:B5:63:06:8B:F9:C2:8A:46:DC

            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: sha256WithRSAEncryption
         9a:5f:7c:2f:6a:8a:7f:69:33:c4:a7:22:1f:cc:84:91:5a:e7:
         0d:e2:2d:5b:b0:30:66:58:7a:65:e4:af:eb:8f:fa:91:13:e1:
         d8:3f:2f:0c:57:f4:46:e6:16:17:bf:53:a6:3b:c0:d1:b1:f2:
         54:4a:90:b9:09:15:03:7b:46:95:a9:d5:00:29:3f:3d:16:48:
         8b:1e:c9:84:8c:bb:7b:5e:ab:c4:30:44:d1:14:42:89:53:6d:
         20:78:23:83:a1:40:eb:f6:d0:4d:03:cf:86:63:46:f9:d4:55:
         f6:01:1c:f5:a1:7d:c6:db:40:ee:82:ee:4a:45:e7:cb:88:81:
         59:fb:b1:21:ba:5e:db:32:ec:1c:f5:03:17:48:90:4d:40:99:
         d0:5d:1d:38:34:26:e2:88:78:98:3c:de:ab:80:e6:a4:f2:c7:
         0a:9b:72:a4:9c:d0:66:2e:27:f8:e3:1d:8f:68:b7:b3:6f:a5:
         0e:51:30:3f:23:6c:8a:ff:f6:07:53:1c:9a:ae:0a:64:17:be:
         c9:7a:45:bf:6c:4b:16:b0:cc:ff:5e:36:86:68:88:a7:ce:b1:
         cb:9a:85:27:67:24:8b:ae:b6:15:e6:21:8a:0f:79:fe:af:b6:
         94:0b:50:3b:be:a3:1e:4e:3b:72:73:d2:65:31:9e:9a:27:99:
         a9:bd:04:70:ea:45:cd:41:fa:4a:b1:93:0e:9a:bd:4c:17:46:
         11:b7:ed:84:4a:47:3e:1d:59:20:0b:c9:0e:14:ca:3b:e2:e9:
         93:e7:71:69:0c:a9:01:24:19:28:85:63:36:f9:bd:bb:cc:76:
         d4:25:e4:97:21:28:96:de:10:21:fc:37:06:97:75:1a:0b:9f:
         24:84:00:81:76:3e:05:4f:7c:1f:f9:31:57:61:f6:2f:bb:7e:
         12:01:88:a0:8b:04:c7:e5:e0:96:8d:b3:26:a4:ec:d2:ec:ae:
         9a:f0:30:b8:17:31:26:6e:ca:5c:23:22:a0:6a:08:15:55:4d:
         e8:07:16:62:3c:24:67:d7:66:2f:06:07:5c:83:c8:e9:3c:b5:
         88:f1:d2:26:6d:81:0f:68:9f:de:0a:a5:0b:e4:ed:ec:29:96:
         12:0e:2b:7b:4b:14:c8:e7:bc:d5:e1:6f:07:11:50:09:7a:08:
         a1:b8:c5:75:a0:f2:ce:87:76:32:7b:d6:47:2a:b1:3e:12:ea:
         ac:74:e1:0b:ce:43:59:a4:ec:16:c0:84:73:d6:2b:df:50:ca:
         f4:46:89:93:80:3f:fe:83:a3:47:12:e1:b9:5f:f9:67:31:be:
         7d:e0:c3:11:e9:49:f7:0e:23:d3:1b:3d:89:f5:42:8c:5c:91:
         0d:13:38:22:2b:58:e8:15
```

Ouput of <kbd>openssl rsa -in ca.key -text -noout
</kbd>:

```
[12/11/22]seed@VM:~/.../PKI$ openssl rsa  -in ca.key -text -noout
Enter pass phrase for ca.key:
RSA Private-Key: (4096 bit, 2 primes)
modulus:
    00:a9:31:28:b5:1b:a1:f2:06:8b:4a:b4:50:32:7a:
    1f:9f:77:2e:35:71:46:0a:09:03:01:25:bf:39:e1:
    25:94:c6:60:6d:5e:28:37:7d:b4:71:74:81:f3:6f:
    89:53:86:83:00:8f:5c:25:96:c7:0f:d9:fd:3a:50:
    77:ff:9a:13:4a:77:65:a3:8e:ae:e3:fd:04:99:9b:
    82:a7:43:aa:39:21:f0:d5:23:e2:3a:b7:46:c3:2c:
    86:e9:c5:d8:ee:6d:d5:98:07:0b:fa:bf:be:d8:c0:
    a0:cc:e3:96:1e:85:f2:bf:41:28:d8:37:90:91:be:
    76:c3:7a:ad:6a:fa:76:7e:28:32:e4:77:4c:63:d1:
    e4:13:5d:71:2c:4d:77:f8:1f:cb:f5:3b:88:3a:67:
    05:eb:50:16:a4:b9:81:50:d3:6a:1c:a6:66:7b:cb:
    46:d4:da:51:02:33:6e:f8:75:50:9a:6a:18:6c:7a:
    9b:20:a3:99:d0:d2:c3:5e:62:a2:c5:51:e5:08:b7:
    c8:2a:b4:99:e8:1c:b3:62:49:ee:2a:e5:d9:f1:86:
    53:5b:2a:90:33:6b:39:48:c3:76:7b:45:ea:a5:03:
    1c:77:51:3a:4f:86:6d:51:3d:f2:fc:b7:cd:1a:40:
    c9:59:25:4b:25:29:d0:ae:ab:12:61:63:5b:4c:d1:
    01:68:35:0a:21:de:50:4e:43:c2:8b:06:d3:87:94:
    87:5d:c6:8b:d5:97:19:79:4c:80:34:d3:46:4b:bd:
    2d:4e:32:cb:ad:79:03:e9:b1:d0:5e:f8:90:d8:0c:
    43:65:22:74:b2:d1:45:db:63:4b:a1:5d:cc:45:16:
    cd:16:81:86:a8:c0:0b:33:0f:91:28:97:79:b2:14:
    58:d3:1c:bb:b1:80:b0:5a:da:57:cf:3d:a3:c0:24:
    d1:9f:17:8d:6d:eb:4b:38:e0:e4:c3:69:2b:32:77:
    98:fc:53:06:6b:99:6c:57:f2:5f:e5:98:bb:ae:54:
    b7:4a:3b:7c:d6:41:ee:c1:40:3d:44:53:a9:f9:ee:
    23:97:11:c2:ca:9c:64:6c:6b:85:73:97:4e:27:72:
    af:1f:c0:08:61:47:e8:8a:3c:ea:d9:95:95:6c:c9:
    89:54:9b:e8:15:55:19:65:ac:a0:cd:b9:34:91:44:
    ab:f6:31:5f:9c:14:bc:dd:e5:73:4c:ef:5f:f3:f2:
    35:3e:d6:79:79:d2:7f:05:e8:11:42:45:90:28:f2:
    f8:63:56:0b:1e:58:10:c6:7e:8e:4a:e0:2a:86:d6:
    ec:c4:cd:da:c9:41:e2:1c:fe:e5:d2:55:9f:01:05:
    be:f2:2e:11:98:da:ff:82:ce:03:ed:c8:7a:0f:fb:
    de:99:59
publicExponent: 65537 (0x10001)
privateExponent:
    31:00:78:de:c3:4b:0b:12:d4:22:e5:c8:58:66:40:
    64:6a:1b:2b:05:4c:98:b9:75:72:4e:a1:6c:bd:05:
    aa:6a:2e:21:5e:e4:dc:f5:7e:5e:61:b5:05:71:67:
    5f:96:94:b8:83:cc:d7:62:2c:f3:2d:5a:87:1a:29:
    37:11:43:c7:0c:7f:96:78:4b:b4:e2:62:03:af:23:
    8f:18:2c:e3:f1:2d:94:3d:99:57:12:1f:df:85:34:
    e9:de:10:6f:35:c6:68:0a:9a:70:9c:3a:45:02:bd:
    4f:ba:16:8f:6e:92:18:cc:61:6d:05:e2:cc:23:52:
    b8:58:fe:82:fe:59:75:3e:65:47:00:3a:52:aa:c6:
    98:c9:36:6e:f3:5c:ec:b3:20:da:3c:cc:be:c5:79:
    d4:66:54:b8:8e:b5:a2:58:28:e2:75:5b:37:3d:6f:
    9d:54:41:a4:16:8b:6c:50:65:f0:e3:0b:81:d7:9c:
    b8:3e:49:dd:4e:3d:a1:47:86:07:0a:2a:00:75:61:
    f6:e4:69:b2:ed:25:13:31:80:56:52:4d:e6:02:d6:
    7f:8f:fb:45:b9:27:55:28:af:57:12:af:db:ec:e3:
    c0:b6:f8:e1:71:78:95:d0:10:61:1b:46:be:f4:c6:
    9c:18:0e:04:8c:70:d1:35:e0:d3:ed:f7:d2:6e:b2:
    2e:28:84:74:5c:f2:cf:46:91:79:1b:c6:28:ef:85:
    dc:77:13:bb:2a:58:62:93:0a:dd:51:55:b3:09:10:
    55:93:94:25:c4:45:25:52:2e:63:62:25:16:95:3c:
    35:39:ff:20:8f:32:e8:e0:60:7f:86:bf:72:22:85:
    32:d2:2a:ec:31:eb:9a:de:38:89:53:73:08:16:8c:
    97:dd:7e:ce:6b:0f:46:a6:75:87:5f:c5:8c:eb:6f:
    d5:60:ee:c1:cb:ed:8d:b3:6b:f8:05:ee:b4:78:c6:
    c1:b5:2c:8a:01:ff:1f:1f:a6:19:30:6d:8c:3c:8d:
    cd:8c:23:7c:14:99:16:a6:df:98:fd:e3:3e:0a:ab:
    c5:9f:f0:23:c2:59:dc:d5:df:67:5a:c6:b0:7d:61:
    85:17:cb:b7:6d:ba:00:91:8b:50:1a:f2:79:78:a6:
    ca:98:66:0d:0b:0b:99:a9:28:24:97:43:94:43:91:
    ee:ec:de:b9:1a:eb:06:20:8c:2c:a7:48:97:38:12:
    c4:b2:b8:2b:96:05:7f:29:9d:ff:0a:52:0f:e6:2b:
    5c:b4:e7:64:9d:2f:53:b7:91:27:ca:0b:8a:59:df:
    36:41:c0:11:d8:fe:c6:7b:e9:f3:a0:29:d1:28:58:
    e8:09:41:e4:b5:ae:d0:e4:a8:60:3e:d6:ef:f1:ba:
    da:81
prime1:
    00:da:77:33:ee:8d:95:42:01:1d:08:79:f0:e2:78:
    a2:16:fb:48:10:61:d0:db:16:61:12:35:fb:b8:00:
    3f:36:16:00:cc:2a:50:fb:69:1c:3a:92:2b:c1:64:
    8b:36:1c:09:93:21:47:05:51:79:3b:e1:82:4a:de:
    1f:5c:1d:eb:75:d3:0c:0b:4a:d9:9b:cd:20:f7:fb:
    84:6c:aa:16:4f:2a:b5:b6:45:c1:8b:39:8b:14:2f:
    e5:2e:df:2e:9d:47:d2:19:68:79:8e:5d:54:fa:61:
    35:aa:e2:52:37:ed:b3:48:2e:db:23:c3:de:b8:10:
    50:b5:06:28:a3:7f:ea:fe:04:5f:a9:76:0d:33:a2:
    99:39:ca:81:d2:25:f7:6e:4a:f1:00:ea:4b:f0:d7:
    72:0a:69:fc:c1:2d:9c:0f:8c:1c:12:e3:da:9a:51:
    b5:d4:2b:cc:c8:e3:6b:1f:22:59:ac:c5:85:7c:af:
    ae:58:b0:41:08:17:59:b5:7f:fc:7f:90:f5:18:d9:
    0d:4e:63:bf:22:16:bb:b6:6a:4f:fd:9f:ab:a4:f2:
    83:a0:5b:e4:ea:c3:a0:4c:2e:c1:0b:0a:03:48:19:
    6f:67:d6:bc:fb:7b:9c:26:03:2c:d8:40:a6:19:be:
    20:3e:6e:b1:a5:5e:66:7b:8a:f8:39:da:a2:b5:cf:
    30:49
prime2:
    00:c6:42:bf:f4:0f:8a:e7:11:5f:5b:4c:c7:9e:27:
    39:db:ef:4f:78:82:0c:2c:c5:70:cf:40:82:bf:a8:
    7c:08:37:cb:49:12:b4:ec:5b:20:cd:1e:fd:f0:7e:
    ec:9d:1a:bb:e7:93:6d:fa:8e:e5:04:5a:80:f3:e4:
    36:27:3b:bd:c7:0f:2e:65:82:fe:51:07:92:2e:93:
    92:fc:50:f1:72:1a:4d:fa:15:21:7d:f6:db:0d:3f:
    f2:5b:1a:9e:cf:c8:39:8b:29:6e:48:ee:3a:9c:8f:
    19:52:13:77:8d:f5:cc:fe:9a:d2:aa:b7:ca:ba:6a:
    fb:7e:c3:11:0b:91:a1:67:29:05:48:a5:9f:5e:06:
    5c:ba:d3:c7:55:61:fa:cc:89:61:49:03:79:7b:42:
    b8:47:75:44:6b:bc:8e:ef:db:50:01:32:0b:4f:9f:
    96:ea:25:62:09:82:f0:c3:a9:3c:ef:3b:54:3e:e9:
    a5:ef:82:90:aa:6e:64:c8:0e:00:aa:dd:98:67:b0:
    bf:65:84:df:77:4d:34:81:4a:af:6f:2f:89:fe:3a:
    b4:6d:00:31:be:b5:f2:23:41:7b:f3:97:0f:90:0b:
    96:3b:59:fa:ea:87:e7:91:d7:b0:05:8a:e6:22:5e:
    7f:2d:34:cb:59:c8:06:df:04:c8:32:65:1f:ed:e2:
    40:91
exponent1:
    00:91:e5:5f:9a:25:95:93:41:d9:18:cb:0e:d2:bf:
    cb:47:db:c2:71:a6:51:6b:ae:d3:5e:ed:0c:51:02:
    61:34:86:97:3b:c1:da:d9:3b:85:ed:9b:a6:7a:fd:
    e1:76:5e:5d:0a:94:03:b1:0a:8b:13:31:73:e8:f9:
    d4:29:99:95:a0:d7:33:c8:ea:d0:ce:9a:bc:34:c0:
    14:dc:d8:ee:13:2a:ab:b5:b1:7a:22:b7:68:29:30:
    1f:37:21:37:29:34:48:9c:4d:48:38:8a:1d:f1:24:
    30:4a:11:e0:e4:96:ea:ce:fe:f3:bc:3b:d7:a6:46:
    c7:0f:4d:b0:a0:18:12:60:57:9d:67:37:7e:73:88:
    58:19:df:22:b9:ac:3f:44:b9:e9:9f:39:d9:43:5b:
    2e:3e:c4:2f:56:f7:55:ac:90:5e:43:43:45:bf:1f:
    68:75:ec:56:53:a6:84:e8:82:f1:2e:4f:ae:e8:e9:
    0e:5f:0e:3e:2f:e0:20:39:f4:e2:34:73:23:2b:d7:
    f0:69:f4:75:35:97:c6:fe:78:9b:38:fe:84:0b:a1:
    25:c4:56:fa:56:ca:14:68:2c:25:21:71:2b:65:e0:
    0e:a5:63:24:4c:32:6d:c2:79:06:5e:d9:35:d4:25:
    43:b5:4e:09:77:2d:c6:f5:24:86:c7:64:3a:9b:7e:
    65:79
exponent2:
    00:ad:eb:92:5e:34:60:42:91:9f:d8:04:c3:bc:3e:
    66:e8:43:c7:b0:4c:4d:07:dd:70:37:af:3c:c3:8a:
    b6:bb:b2:ce:36:dd:1d:2f:96:45:71:0b:75:f2:ca:
    35:21:20:79:a4:0d:55:d6:0e:12:63:3e:4d:8f:26:
    2c:47:40:86:1b:a0:7a:af:fc:38:c2:b6:64:8b:4d:
    54:0c:d9:a8:e4:d2:a4:82:f4:94:7b:de:d8:8c:88:
    03:3f:de:5b:60:a5:21:ad:ad:7b:9c:a8:b7:6b:ed:
    b0:65:aa:c4:1f:19:78:6a:05:41:37:17:a1:d4:e4:
    d2:98:81:e0:6b:08:a6:d1:4b:4f:e2:49:c0:43:08:
    4b:c2:6c:d3:99:58:29:5d:d2:4a:30:75:c6:d4:d5:
    53:b9:03:eb:30:a3:a9:b4:49:ec:a6:0f:d3:92:56:
    ca:59:be:cf:80:ce:88:0c:ec:62:92:ee:b5:d9:b6:
    b7:a5:23:21:6b:11:0a:81:e0:9e:bf:45:43:53:fa:
    dd:fb:dd:92:f7:22:18:24:2f:73:34:93:3c:77:73:
    e2:21:18:a1:8a:ce:2b:8a:b8:00:57:50:b6:0b:43:
    ce:d7:63:f8:d4:52:c2:56:d3:22:0b:ca:ac:55:8c:
    15:fe:7f:28:c0:2a:d3:b4:42:8a:a8:82:c3:7e:b8:
    12:b1
coefficient:
    00:d6:73:4a:4b:2f:8c:a9:38:6b:00:a5:9b:46:82:
    42:cc:eb:a6:ee:6b:26:36:28:a4:f1:9e:df:a8:9f:
    90:7f:fe:7c:e1:44:b5:1e:c9:cd:53:c9:41:ed:25:
    b8:09:02:9c:48:d9:28:29:aa:4e:7c:1e:c3:4b:69:
    02:11:6d:53:b2:1f:b5:d8:62:e1:7e:d7:e9:9a:96:
    50:73:0d:c4:6b:d4:81:4a:2f:d3:69:44:ea:59:52:
    53:57:b0:7b:d3:01:b0:62:a0:7a:27:da:93:3e:33:
    ba:18:1f:85:ab:b6:5c:b7:fa:6f:65:04:c3:6b:f9:
    0c:cf:9a:71:da:1c:2e:9e:85:94:d0:28:94:92:53:
    5d:d0:51:2a:62:47:5e:53:b9:d3:70:26:20:6a:73:
    93:6f:db:c8:21:c7:cc:7e:9e:5f:65:38:ef:f5:f5:
    a5:18:9c:fd:fa:74:ef:46:0a:e8:66:fa:0d:17:5d:
    f7:da:c2:2b:23:12:20:b5:de:f8:5f:19:d4:5b:d3:
    37:0a:76:be:42:6f:32:cd:f4:a3:7b:6d:c4:a6:61:
    e1:27:e8:0c:a7:c4:8f:4d:42:ad:12:bd:d5:e0:ec:
    b6:8e:3e:0c:f4:7a:c7:4c:85:44:d4:c5:37:20:17:
    aa:45:b2:bc:3e:ba:5b:c8:00:ae:80:70:b0:87:1f:
    e7:54
```

#### Questions

- **What part of the certificate indicates this is a CA’s certificate?**
 

CA:TRUE

![](https://i.imgur.com/lAhg19l.png)


- **What part of the certificate indicates this is a self-signed certificate?**

The certificate is self signed because the subject and the authority key are the same.

![](https://i.imgur.com/DhFULaV.png)


- **In the RSA algorithm, we have a public exponent e, a private exponent d, a modulus n, and two secret numbers p and q, such that n = pq. Please identify the values for these elements in your certificate and key files.**

These values (modulus, publicExponent, privateExponent, prime1, prime2), are present in the output of <kbd>openssl rsa -in ca.key -text -noout</kbd> as seen above.

### Task 2

For this task, we used the following command to generate a CSR for `www.brufrin2022.com`:

```
openssl req -newkey rsa:2048 -sha256  \-keyout server.key   -out server.csr  \-subj "/CN=www.brufrin2022.com/O=Brufrin2022 Inc./C=US" \-passout pass:dees
```

After this, we ran:

```
[12/11/22]seed@VM:~/.../PKI$ openssl req -in server.csr -text -noout
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: CN = www.brufrin2022.com, O = Brufrin2022 Inc., C = US
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:c3:05:46:60:94:05:45:4d:f8:b1:c3:0f:cc:d1:
                    c7:4f:df:2a:b2:67:80:9f:86:4b:00:23:f9:73:43:
                    4b:45:69:1c:e4:e8:52:4b:46:35:4a:8c:df:70:81:
                    40:a2:92:f4:70:e3:4d:b2:08:fc:23:c4:ea:7d:c1:
                    43:35:75:e7:b9:af:95:cc:23:64:36:f2:e8:f5:77:
                    29:94:88:7c:36:e3:ca:81:de:cc:0c:f7:5f:6a:c7:
                    3b:27:c7:77:c3:0d:c2:82:5a:eb:aa:14:06:fa:25:
                    00:17:6c:2c:7f:78:dd:49:eb:2f:d1:8b:9e:39:b2:
                    15:50:09:f6:01:0d:d7:55:fe:06:6e:23:07:88:43:
                    38:98:eb:33:98:5e:23:5f:17:d3:d8:78:77:87:21:
                    10:51:ed:6a:cb:2e:a8:2c:c9:cb:95:f8:70:01:f7:
                    7c:2d:97:47:d1:ca:b0:e4:d9:c8:f1:57:76:cc:fa:
                    27:68:1a:fb:fd:02:cc:8c:16:de:5d:f0:9d:ce:c0:
                    0b:25:8a:f4:20:ef:ad:fa:3b:4e:03:7b:05:b3:fe:
                    72:7f:7e:ad:76:36:14:72:f1:40:be:b0:4b:d0:be:
                    f6:96:58:23:4d:da:ae:58:27:a5:73:af:5d:b1:8f:
                    49:49:43:60:89:7b:62:c6:6b:d1:72:cc:13:8d:84:
                    c9:f9
                Exponent: 65537 (0x10001)
        Attributes:
            a0:00
    Signature Algorithm: sha256WithRSAEncryption
         99:4d:d1:f7:07:4b:d6:eb:e3:a3:0a:78:ce:48:11:78:b7:6e:
         84:6f:44:a1:0e:22:6e:a7:55:3f:04:68:e1:c0:e0:d4:55:be:
         fb:72:43:22:08:3a:39:e0:5c:33:b0:08:51:c5:f8:29:c7:bb:
         cf:b3:67:4c:08:8e:d7:52:5e:e4:d1:bf:54:63:2b:41:98:42:
         91:7f:74:96:0f:1a:a8:82:d7:8d:af:7a:f4:50:1e:6b:0b:26:
         75:bb:0d:f7:33:9a:aa:69:de:36:54:a0:c9:69:a0:91:fe:cd:
         55:3a:fb:d5:40:d9:e7:9d:91:22:f9:b5:96:6d:2b:f4:51:0d:
         66:82:0b:46:2e:3e:0a:4c:fd:e9:44:1a:aa:5d:1e:b1:ea:82:
         99:00:3a:db:78:dd:31:47:e6:33:1e:23:e2:c2:26:ba:71:88:
         c8:51:11:ac:42:0e:63:f8:de:ea:7d:c5:8f:0e:75:c1:9f:07:
         15:38:a2:ea:a2:08:65:fd:de:05:74:9d:a8:25:cf:d1:69:87:
         56:da:bf:5f:c6:08:10:f0:78:d8:18:90:bf:99:fb:36:08:f8:
         09:50:b6:a5:b1:b9:03:fe:ef:41:af:a2:63:75:24:22:7e:5c:
         f9:b6:a4:0e:37:03:e1:37:86:6c:14:4e:3e:d3:f6:7a:dd:56:
         4b:10:ca:b1

```

And:
```
[12/11/22]seed@VM:~/.../PKI$ openssl rsa -in server.key -text -noout
Enter pass phrase for server.key:
RSA Private-Key: (2048 bit, 2 primes)
modulus:
    00:c3:05:46:60:94:05:45:4d:f8:b1:c3:0f:cc:d1:
    c7:4f:df:2a:b2:67:80:9f:86:4b:00:23:f9:73:43:
    4b:45:69:1c:e4:e8:52:4b:46:35:4a:8c:df:70:81:
    40:a2:92:f4:70:e3:4d:b2:08:fc:23:c4:ea:7d:c1:
    43:35:75:e7:b9:af:95:cc:23:64:36:f2:e8:f5:77:
    29:94:88:7c:36:e3:ca:81:de:cc:0c:f7:5f:6a:c7:
    3b:27:c7:77:c3:0d:c2:82:5a:eb:aa:14:06:fa:25:
    00:17:6c:2c:7f:78:dd:49:eb:2f:d1:8b:9e:39:b2:
    15:50:09:f6:01:0d:d7:55:fe:06:6e:23:07:88:43:
    38:98:eb:33:98:5e:23:5f:17:d3:d8:78:77:87:21:
    10:51:ed:6a:cb:2e:a8:2c:c9:cb:95:f8:70:01:f7:
    7c:2d:97:47:d1:ca:b0:e4:d9:c8:f1:57:76:cc:fa:
    27:68:1a:fb:fd:02:cc:8c:16:de:5d:f0:9d:ce:c0:
    0b:25:8a:f4:20:ef:ad:fa:3b:4e:03:7b:05:b3:fe:
    72:7f:7e:ad:76:36:14:72:f1:40:be:b0:4b:d0:be:
    f6:96:58:23:4d:da:ae:58:27:a5:73:af:5d:b1:8f:
    49:49:43:60:89:7b:62:c6:6b:d1:72:cc:13:8d:84:
    c9:f9
publicExponent: 65537 (0x10001)
privateExponent:
    3e:2f:13:66:be:2c:04:12:3d:a7:68:dc:43:e1:ec:
    1c:b2:bb:29:91:c9:38:94:98:9b:9d:dc:ef:7c:d8:
    a6:74:42:cb:56:ac:ce:e5:bf:1e:5b:56:ef:c7:b6:
    f5:5f:c8:63:aa:86:de:aa:f0:c2:f3:0a:16:39:26:
    96:08:57:70:24:e5:ad:e6:e7:10:82:59:f7:d3:1c:
    46:09:53:1a:29:7e:2b:f4:ff:b9:6e:b3:55:17:db:
    eb:ee:35:68:d3:9d:5e:f5:60:c9:a5:83:28:05:de:
    46:99:ae:82:a2:e6:64:a8:82:61:dd:94:01:2f:a0:
    8e:19:ef:00:1d:0a:b9:97:2c:75:91:f0:39:f3:7a:
    d2:98:7b:5a:6a:9d:d9:9e:5f:ba:cc:05:7e:fd:bd:
    2d:b7:13:a2:91:6c:b9:ef:41:77:a2:a3:0f:9a:ff:
    81:6d:2d:22:2e:93:4b:8a:9a:79:eb:34:63:0e:d1:
    02:f8:e3:1c:4b:4e:78:b4:f2:70:f3:be:da:d2:63:
    b3:a1:b7:54:3f:05:32:c3:d0:fc:78:35:01:45:db:
    eb:98:9a:1f:61:bb:0e:2c:c9:2d:a2:2c:0a:b0:7b:
    1b:af:ec:70:c7:8d:5f:5a:d3:c5:c5:78:ea:7d:42:
    77:78:26:a2:4a:99:7a:bc:f8:45:93:56:c4:7f:58:
    75
prime1:
    00:ed:0f:62:f0:ce:b5:6c:ae:26:85:73:63:01:85:
    fa:eb:25:e4:d9:0a:19:4d:0d:36:e2:8e:87:2c:7c:
    47:d2:ac:17:0c:cc:31:4f:31:0e:97:4b:bb:57:81:
    f1:c1:da:96:d0:09:e5:10:24:cb:3a:b5:95:06:b6:
    85:8a:bf:4c:43:e1:ce:79:c6:e3:0c:22:54:ab:16:
    8c:5e:9c:5b:4a:59:6c:7c:b6:11:e3:b6:c6:90:75:
    8b:33:c7:8b:f8:5f:03:a7:46:36:c6:b3:21:43:a5:
    de:93:a2:dd:a1:02:97:e7:ff:7e:f7:8a:f6:88:c0:
    09:79:8e:9c:73:53:7a:a1:07
prime2:
    00:d2:9a:0c:ea:1f:33:4d:ee:6d:6e:b0:13:01:5b:
    52:47:c8:ca:3a:7f:c8:a8:75:67:e7:5d:ed:10:10:
    5b:38:07:a2:c1:0f:03:3b:2d:fe:4c:e2:ad:82:a5:
    12:a8:d0:7c:bb:05:70:f1:da:30:d2:41:8e:40:7c:
    99:56:31:8c:67:5e:a6:7d:70:15:54:27:bd:16:3f:
    76:e1:30:4c:e1:b1:32:0f:72:38:13:cd:79:ff:28:
    7c:5d:e9:77:4a:6d:f6:df:e1:3c:e3:1e:84:13:72:
    f5:b7:17:cb:c9:7f:7e:45:81:d7:bd:81:63:8b:91:
    75:93:9b:2d:6d:c7:e9:7c:ff
exponent1:
    00:ac:1f:cc:e6:2e:20:9a:dd:c4:08:87:a4:6e:79:
    ba:9b:bc:72:f2:88:1b:a0:cf:a4:77:51:a7:a2:4c:
    46:d6:17:af:d0:d1:fe:47:92:c6:16:62:9d:8f:47:
    41:a3:50:b4:ca:2f:35:0b:c8:bb:6b:50:66:f9:6d:
    d3:7e:cf:b1:6f:64:68:48:11:79:cf:d8:a9:83:64:
    26:dd:97:47:cd:af:2a:4f:4e:df:a4:68:94:ba:55:
    2e:92:95:23:f3:5e:01:c8:15:fa:35:c1:e0:b8:3e:
    9a:62:b6:11:98:13:ca:fa:5f:8f:ef:eb:0d:60:73:
    97:2d:94:b7:d2:20:dd:dc:47
exponent2:
    00:c2:d3:a8:a6:dd:fe:44:56:11:fe:97:fc:bd:00:
    92:79:be:12:f7:53:47:7a:30:42:d3:13:5d:3f:c3:
    21:e0:0f:90:4d:31:6a:37:d1:30:b4:47:ef:64:30:
    f9:b6:1a:49:89:6a:5b:36:22:37:90:0a:fd:62:42:
    e2:47:8e:c6:e8:c9:f3:13:90:20:eb:1d:68:1b:b0:
    d2:75:38:8d:a7:2c:99:b7:18:5f:30:52:a2:4d:9e:
    52:8f:3e:70:10:f6:f1:af:e3:5a:c4:71:72:95:db:
    7f:dc:c5:b2:cc:d1:99:2b:0c:17:5d:44:d9:a6:40:
    06:99:6a:b0:f8:22:3c:aa:59
coefficient:
    00:dd:7e:20:3f:31:8d:23:21:3a:bf:d6:0d:c2:8d:
    08:af:42:45:45:55:30:a0:c9:26:fc:7a:2d:00:14:
    f8:a3:2a:bb:39:a3:87:cd:6e:4b:b5:7b:99:ed:8f:
    3e:05:20:61:32:0e:a1:4a:7c:0e:3d:ed:50:e1:7a:
    7d:81:9c:8a:be:e2:e8:da:41:fa:92:ce:06:42:48:
    03:c0:7b:e8:13:a3:f1:7f:f7:52:0c:c9:c3:56:7c:
    b2:ca:52:38:0c:6e:36:77:3e:1a:7b:64:aa:5d:5e:
    a3:8e:4f:2e:b7:a1:1f:92:e6:73:3c:dd:01:49:6a:
    cc:9d:f4:76:a3:de:22:f4:4d

```

We also added the subjectAltName field, which allows a certificate to have multiple names.

```
-addext "subjectAltName = DNS:www.brufrin2022.com,  \DNS:www.brufrin2022A.com, \DNS:www.brufrin2022B.com"
```

We added two alternative names:

![](https://i.imgur.com/YWrPUNa.png)


### Task 3

For this task, the CSR file needs to have the CA’s signature to form a certificate, so we'll use the one we defined in Task 1. (openssl.cnf)

```
[12/11/22]seed@VM:~/.../PKI$ openssl ca -config openssl.cnf -policy policy_anything \-md sha256 -days 3650 \-in server.csr -out server.crt -batch \-cert ca.crt -keyfile ca.key
Using configuration from openssl.cnf
Enter pass phrase for ca.key:
Check that the request matches the signature
Signature ok
Certificate Details:
        Serial Number: 4098 (0x1002)
        Validity
            Not Before: Dec 11 17:02:08 2022 GMT
            Not After : Dec  8 17:02:08 2032 GMT
        Subject:
            countryName               = US
            organizationName          = Brufrin2022 Inc.
            commonName                = www.brufrin2022.com
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            Netscape Comment: 
                OpenSSL Generated Certificate
            X509v3 Subject Key Identifier: 
                77:8E:AA:3A:52:32:2D:3D:C9:19:C6:E3:93:7E:2C:E8:52:29:F1:1C
            X509v3 Authority Key Identifier: 
                keyid:3B:EB:06:9D:23:95:1C:4E:2F:74:51:B5:63:06:8B:F9:C2:8A:46:DC

Certificate is to be certified until Dec  8 17:02:08 2032 GMT (3650 days)

Write out database with 1 new entries
Data Base Updated

```

After uncommenting the following line from `openssl.cnf`
```
copy_extensions = copy
```
And by running once again the command `openssl x509 -in server.crt -text -noout`  to print out the decoded content of the certificate, we can see the URLs were added:

![](https://i.imgur.com/IgPxYkd.png)


### Task 4

Following the example provided HTTPS site for `www.bank32.com` we decided to create our own directory named `task4` inside our `PKI` folder.

Inside this directory the following elements are present: a folder named `certs`, a `Dockerfile`, a `brufrin2022_apache_ssl.cnf` file and the two index.html provided files, `index.html` and `index_red.html`.

In the `certs` folder, `ca.crt`, `server.crt` and `server.key` files are present.

After that, we needed to change the `Dockerfile`, and the content is as seen below:

```
FROM handsonsecurity/seed-server:apache-php

ARG WWWDIR=/var/www/brufrin2022

COPY ./index.html ./index_red.html $WWWDIR/
COPY ./brufrin2022_apache_ssl.conf /etc/apache2/sites-available
COPY ./certs/server.crt ./certs/server.key /certs/

RUN chmod 400 /certs/server.key \
    && chmod 644 $WWWDIR/index.html \
    && chmod 644 $WWWDIR/index_red.html \
    && a2ensite brufrin2022_apache_ssl

CMD tail -f /dev/null
```

Then, in the `brufrin2022_apache_ssl.cnf`:

```
<VirtualHost *:443>
    DocumentRoot /var/www/brufrin2022
    ServerName     www.brufrin2022.com
    ServerAlias    www.brufrin2022A.com
    ServerAlias    www.brufrin2022B.com
    DirectoryIndex index.html
    SSLEngine On
    SSLCertificateFile /certs/server.crt
    SSLCertificateKeyFile /certs/server.key
</VirtualHost>

<VirtualHost *:80>
    DocumentRoot /var/www/brufrin2022
    ServerName www.brufrin2022.com
    DirectoryIndex index_red.html
</VirtualHost>
```

We changed the docker-compose to have `build: ./task4` and after `dcbuild `and `dcup` we accessed the container using `dockps` and then `docksh <id>`.

Inside the container we ran `service apache2 start`:
    
![](https://i.imgur.com/K11H5ro.png)
    
When we entered `https://www.brufrin2022.com` firefox gave us a security warning:
    
![](https://i.imgur.com/k9kRZZ2.png)

Because Firefox in its back of certificates, only has highly secure certificates, a self-signed certificate is a reason to launch a warning.

To solve this, we needed to add our CA to the trusted authorities of the browser:

![](https://i.imgur.com/WVcIemT.png)

After adding it, we can successfully enter our server:
    
![](https://i.imgur.com/qr6XXfe.png)


### Task 5

This task consisted of three steps. 

In step 1, setting up the malicious website, we simply changed the apache file in the ServerName field, using the website we wanted to try to intercept communication: `www.twitter.com`.

```
<VirtualHost *:443>
    DocumentRoot /var/www/brufrin2022
    ServerName     www.twitter.com
    ServerAlias    www.brufrin2022.com
    ServerAlias    www.brufrin2022A.com
    ServerAlias    www.brufrin2022B.com
    DirectoryIndex index.html
    SSLEngine On
    SSLCertificateFile /certs/server.crt
    SSLCertificateKeyFile /certs/server.key
</VirtualHost>

<VirtualHost *:80>
    DocumentRoot /var/www/brufrin2022
    ServerName www.twitter.com
    DirectoryIndex index_red.html
</VirtualHost>
```

In step 2, becoming the man in the middle, we simply modify the victim’s machine’s /etc/hosts file to emulate the result of a DNS cache positing attack by mapping the hostname `www.twitter.com` to our malicious web server:

```
10.9.0.80 www.twitter.com
```

In the final step, step 3, browse the target website, when we tried to access `www.twitter.com`, the browser displayed the following warning:

![](https://i.imgur.com/JpKnQih.png)

This happens because the certificate that we are using to sign `www.twitter.com` was created for `www.brufrin2022.com`. This kind of websites detect these mismatches in certificates and alert the user.
    
### Task 6

To successfully perform a MITM attack, we needed to create the certificate to include the `www.twitter.com` address. This can be done with the following command:

```
[12/12/22]seed@VM:~/.../PKI$ openssl req -newkey rsa:2048 -sha256 -keyout server.key -out server.csr -subj "/CN=www.twitter.com/O=Brufrin2022 Inc./C=PT" -passout pass:dees -addext "subjectAltName = DNS:www.twitter.com, DNS:www.brufrin2022.com, DNS:www.brufrin2022A.com, DNS:www.brufrin2022B.com"
Generating a RSA private key
............................+++++
......................................+++++
writing new private key to 'server.key'
-----
```   
After that, we need to generate the certificate itself, with the following command:

```
[12/12/22]seed@VM:~/.../PKI$ openssl ca -config openssl.cnf -policy policy_anything -md sha256 -days 3650 -in server.csr -out server.crt -batch -cert ca.crt -keyfile ca.key
Using configuration from openssl.cnf
Enter pass phrase for ca.key:
Check that the request matches the signature
Signature ok
Certificate Details:
        Serial Number: 4101 (0x1005)
        Validity
            Not Before: Dec 12 11:39:03 2022 GMT
            Not After : Dec  9 11:39:03 2032 GMT
        Subject:
            countryName               = PT
            organizationName          = Brufrin2022 Inc.
            commonName                = www.twitter.com
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            Netscape Comment: 
                OpenSSL Generated Certificate
            X509v3 Subject Key Identifier: 
                C3:EC:0F:62:65:D6:7D:BC:A0:83:3A:EE:27:6F:65:13:04:B8:0C:00
            X509v3 Authority Key Identifier: 
                keyid:3B:EB:06:9D:23:95:1C:4E:2F:74:51:B5:63:06:8B:F9:C2:8A:46:DC

            X509v3 Subject Alternative Name: 
                DNS:www.twitter.com, DNS:www.brufrin2022.com, DNS:www.brufrin2022A.com, DNS:www.brufrin2022B.com
Certificate is to be certified until Dec  9 11:39:03 2032 GMT (3650 days)

Write out database with 1 new entries
Data Base Updated
```

With the certificate created, we needed to restart our server in order to successfully perform the attack. After restarting the server with the new certificates, and updating the ssl config file to:

```
<VirtualHost *:443>
    DocumentRoot /var/www/brufrin2022
    ServerName	www.twitter.com
    ServerAlias www.brufrin2022.com
    ServerAlias www.brufrin2022A.com
    ServerAlias www.brufrin2022B.com
    DirectoryIndex index.html
    SSLEngine On
    SSLCertificateFile /certs/server.crt
    SSLCertificateKeyFile /certs/server.key
</VirtualHost>

<VirtualHost *:80>
    DocumentRoot /var/www/brufrin2022
    ServerName www.twitter.com
    DirectoryIndex index_red.html
</VirtualHost>
```

We successfully entered `www.twitter.com` and the browser did not raise any suspicion:

![](https://i.imgur.com/h1aS7NW.png)

