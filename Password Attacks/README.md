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
###Introduction to John The Ripper
```
[/htb]$ john --single passwd

Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
```
```
[/htb]$ john --wordlist=<wordlist_file> <hash_file>
```
```
[/htb]$ john --incremental <hash_file>
```
```
[/htb]$ hashid -j 193069ceb0461e1d40d216e32c79c704
```
```
afs	                        john--format=afs [...] <hash_file>	      AFS (Andrew File System) password hashes
bfegg	                      john--format=bfegg [...] <hash_file>	    bfegg hashes used in Eggdrop IRC bots
bf	                        john--format=bf [...] <hash_file>	      Blowfish-based crypt(3) hashes
bsdi	                     john--format=bsdi [...] <hash_file>	    BSDi crypt(3) hashes
crypt(3)	                 john--format=crypt [...] <hash_file>	    Traditional Unix crypt(3) hashes
des	                       john--format=des [...] <hash_file>	      Traditional DES-based crypt(3) hashes
dmd5	                     john--format=dmd5 [...] <hash_file>	    DMD5 (Dragonfly BSD MD5) password hashes
dominosec	                 john--format=dominosec [...] <hash_file>	IBM Lotus Domino 6/7 password hashes
EPiServer SID hashes	     john--format=episerver [...] <hash_file>	EPiServer SID (Security Identifier) password hashes
hdaa	                     john--format=hdaa [...] <hash_file>	    hdaa password hashes used in Openwall GNU/Linux
hmac-md5	                 john--format=hmac-md5 [...] <hash_file>	hmac-md5 password hashes
hmailserver	               john--format=hmailserver [...] <hash_file>	hmailserver password hashes
ipb2	                    john --format=ipb2 [...] <hash_file>     	Invision Power Board 2 password hashes
krb4	                    john --format=krb4 [...] <hash_file>	Kerberos 4 password hashes
krb5	                    john--format=krb5 [...] <hash_file>	Kerberos 5 password hashes
LM	                      john --format=LM [...] <hash_file>	LM (Lan Manager) password hashes
lotus5	                  john --format=lotus5 [...] <hash_file>	Lotus Notes/Domino 5 password hashes
mscash	                  john --format=mscash [...] <hash_file>	MS Cache password hashes
mscash2	                  john --format=mscash2 [...] <hash_file>	MS Cache v2 password hashes
mschapv2	                john --format=mschapv2 [...] <hash_file>	MS CHAP v2 password hashes
mskrb5	                john --format=mskrb5 [...] <hash_file>	MS Kerberos 5 password hashes
mssql05	                john --format=mssql05 [...] <hash_file>	MS SQL 2005 password hashes
mssql	                  john --format=mssql [...] <hash_file>	MS SQL password hashes
mysql-fast	            john --format=mysql-fast [...] <hash_file>	MySQL fast password hashes
mysql	                  john --format=mysql [...] <hash_file>	MySQL password hashes
mysql-sha1	            john --format=mysql-sha1 [...] <hash_file>	MySQL SHA1 password hashes
NETLM	                  john --format=netlm [...] <hash_file>	NETLM (NT LAN Manager) password hashes
NETLMv2	                john --format=netlmv2 [...] <hash_file>	NETLMv2 (NT LAN Manager version 2) password hashes
NETNTLM	                john --format=netntlm [...] <hash_file>	NETNTLM (NT LAN Manager) password hashes
NETNTLMv2	              john --format=netntlmv2 [...] <hash_file>	NETNTLMv2 (NT LAN Manager version 2) password hashes
NEThalfLM	              john --format=nethalflm [...] <hash_file>	NEThalfLM (NT LAN Manager) password hashes
md5ns	                  john --format=md5ns [...] <hash_file>	md5ns (MD5 namespace) password hashes
nsldap	                john --format=nsldap [...] <hash_file>	nsldap (OpenLDAP SHA) password hashes
ssha	                  john --format=ssha [...] <hash_file>	ssha (Salted SHA) password hashes
NT	                    john --format=nt [...] <hash_file>	NT (Windows NT) password hashes
openssha	john --format=openssha [...] <hash_file>	OPENSSH private key password hashes
oracle11	john --format=oracle11 [...] <hash_file>	Oracle 11 password hashes
oracle	john --format=oracle [...] <hash_file>	Oracle password hashes
pdf	john --format=pdf [...] <hash_file>	PDF (Portable Document Format) password hashes
phpass-md5	john --format=phpass-md5 [...] <hash_file>	PHPass-MD5 (Portable PHP password hashing framework) password hashes
phps	john --format=phps [...] <hash_file>	PHPS password hashes
pix-md5	john --format=pix-md5 [...] <hash_file>	Cisco PIX MD5 password hashes
po	john --format=po [...] <hash_file>	Po (Sybase SQL Anywhere) password hashes
rar	john --format=rar [...] <hash_file>	RAR (WinRAR) password hashes
raw-md4	john --format=raw-md4 [...] <hash_file>	Raw MD4 password hashes
raw-md5	john --format=raw-md5 [...] <hash_file>	Raw MD5 password hashes
raw-md5-unicode	john --format=raw-md5-unicode [...] <hash_file>	Raw MD5 Unicode password hashes
raw-sha1	john --format=raw-sha1 [...] <hash_file>	Raw SHA1 password hashes
raw-sha224	john --format=raw-sha224 [...] <hash_file>	Raw SHA224 password hashes
raw-sha256	john --format=raw-sha256 [...] <hash_file>	Raw SHA256 password hashes
raw-sha384	john --format=raw-sha384 [...] <hash_file>	Raw SHA384 password hashes
raw-sha512	john --format=raw-sha512 [...] <hash_file>	Raw SHA512 password hashes
salted-sha	john --format=salted-sha [...] <hash_file>	Salted SHA password hashes
sapb	john --format=sapb [...] <hash_file>	SAP CODVN B (BCODE) password hashes
sapg	john --format=sapg [...] <hash_file>	SAP CODVN G (PASSCODE) password hashes
sha1-gen	john --format=sha1-gen [...] <hash_file>	Generic SHA1 password hashes
skey	john --format=skey [...] <hash_file>	S/Key (One-time password) hashes
ssh	john --format=ssh [...] <hash_file>	SSH (Secure Shell) password hashes
sybasease	john --format=sybasease [...] <hash_file>	Sybase ASE password hashes
xsha	john --format=xsha [...] <hash_file>	xsha (Extended SHA) password hashes
zip	john --format=zip [...] <hash_file>	ZIP (WinZip) password hashes
```
### Cracking files
