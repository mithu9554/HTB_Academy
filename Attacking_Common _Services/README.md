
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
*  SMB	              FTP	          Email	              Databases
*  smbclient	        ftp	          Thunderbird	        mssql-cli
*  CrackMapExec	      lftp	        Claws	              mycli
*  SMBMap	            ncftp	        Geary	              mssqlclient.py
*  Impacket	          filezilla	    MailSpring	        dbeaver
*  psexec.py	        crossftp	    mutt	              MySQL Workbench
*  smbexec.py		                    mailutils	          SQL Server Management Studio or SSMS
*  sendEmail	
*  swaks	
*  sendmail
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

