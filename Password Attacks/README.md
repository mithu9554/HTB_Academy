# [HTB] Command Injections
## Introduction to Password Cracking

```
bmdyy@htb:~$ echo -n Soccer06! | md5sum
40291c1d19ee11a7df8495c4cccefdfa  -

bmdyy@htb:~$ echo -n Soccer06! | sha256sum
a025dc6fabb09c2b8bfe23b5944635f9b68433ebd9a1a09453dd4fee00766d93
```

```
mdmithu@htb[/htb]$ echo -n Th1sIsTh3S@lt_Soccer06! | md5sum

90a10ba83c04e7996bc53373170b5474  -
```
#### Dictionary attack
```
[/htb]$ head --lines=20 /usr/share/wordlists/rockyou.txt 

123456
12345
123456789
password
iloveyou
princess
1234567
rockyou
12345678
abc123
nicole
```
