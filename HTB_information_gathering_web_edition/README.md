# [HTB] Command Injections
### Search Operators
```
site:example.com
inurl:login
filetype:pdf
intitle:"confidential report"
intext:"password reset"
cache:example.com
link:example.com
related:example.com
info:example.com
define:phishing
site:example.com numrange:1000-2000
allintext:admin password reset
allinurl:admin panel
allintitle:confidential report 2023
site:example.com AND (inurl:admin OR inurl:login)
"linux" OR "ubuntu" OR "debian"
site:bank.com NOT inurl:login
site:socialnetwork.com filetype:pdf user* manual
site:ecommerce.com "price" 100..500
"information security policy"
site:news.com -inurl:sports
```
```
Finding Login Pages:
site:example.com inurl:login
site:example.com (inurl:login OR inurl:admin)
Identifying Exposed Files:
site:example.com filetype:pdf
site:example.com (filetype:xls OR filetype:docx)
Uncovering Configuration Files:
site:example.com inurl:config.php
site:example.com (ext:conf OR ext:cnf) (searches for extensions commonly used for configuration files)
Locating Database Backups:
site:example.com inurl:backup
site:example.com filetype:sql
https://www.exploit-db.com/google-hacking-database
```
## WHOIS

>**Q. Perform a WHOIS lookup against the paypal.com domain. What is the registrant Internet Assigned Numbers Authority (IANA) ID number?**

```sh
whois paypal.com
```
### Automating Passive Subdomain Enumeration Tools:
``` Baidu	    Baidu search engine. ```

``` Bufferoverun	    Uses data from Rapid7's Project Sonar - www.rapid7.com/research/project-sonar/ ```

``` cCrtsh	    Comodo Certificate search. ```

``` Hackertarget	  Online vulnerability scanners and network intelligence to help organizations. ```

``` Otx    	AlienVault Open Threat Exchange - https://otx.alienvault.com ```

``` Rapiddns	    DNS query tool, which makes querying subdomains or sites using the same IP easy. ```

``` Sublist3r	    Fast subdomains enumeration tool for penetration testers ```

``` Threatcrowd	    Open source threat intelligence. ```

``` Threatminer	    Data mining for threat intelligence. ```

``` Trello	    Search Trello boards (Uses Google search) ```

``` Urlscan	    A sandbox for the web that is a URL and website scanner. ```

``` Vhost	    Bing virtual hosts search. ```

``` Virustotal	    Domain search. ```

``` Zoomeye	    A Chinese version of Shodan. ``` 

### To automate this, we will create a file called sources.txt with the following contents.
```
[/htb]$ cat sources.txt

baidu
bufferoverun
crtsh
hackertarget
otx
projectdiscovery
rapiddns
sublist3r
threatcrowd
trello
urlscan
vhost
virustotal
zoomeye
```
```
[/htb]$ export TARGET="facebook.com"
[/htb]$ cat sources.txt | while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}_${TARGET}";done

<SNIP>
*******************************************************************
*  _   _                                            _             *
* | |_| |__   ___    /\  /\__ _ _ ____   _____  ___| |_ ___ _ __  *
* | __|  _ \ / _ \  / /_/ / _` | '__\ \ / / _ \/ __| __/ _ \ '__| *
* | |_| | | |  __/ / __  / (_| | |   \ V /  __/\__ \ ||  __/ |    *
*  \__|_| |_|\___| \/ /_/ \__,_|_|    \_/ \___||___/\__\___|_|    *
*                                                                 *
* theHarvester 4.0.0                                              *
* Coded by Christian Martorella                                   *
* Edge-Security Research                                          *
* cmartorella@edge-security.com                                   *
*                                                                 *
*******************************************************************


[*] Target: facebook.com

[*] Searching Urlscan.

```
```
[/htb]$ cat *.json | jq -r '.hosts[]' 2>/dev/null | cut -d':' -f 1 | sort -u > "${TARGET}_theHarvester.txt"
```
## crt.sh lookup
```
curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[]
 | select(.name_value | contains("dev")) | .name_value' | sort -u
```

>**Q. What is the admin email contact for the tesla.com domain (also in-scope for the Tesla bug bounty program)?**

```sh
whois tesla.com | "admin"
```

## DNS

>**Q. Which IP address maps to inlanefreight.com?**

```sh
nslookup -query=A inlanefreight.com
```

>**Q. Which subdomain is returned when querying the PTR record for 173.0.87.51?**

```sh
nslookup -query=PTR 173.0.87.51
```
>**Q. What is the first mailserver returned when querying the MX records for paypal.com?**

```sh
nslookup -query=MX paypal.com
```

## Active Infrastructure Identification

>**Q. What Apache version is running on app.inlanefreight.local? (Format: 0.0.0)**

```sh
curl -I "http://10.129.194.206"
```

>**Q. Which CMS is used on app.inlanefreight.local? (Format: word)**

```sh
nano /etc/hosts
```

```sh
10.129.194.206 app.inlanefreight.local dev.inlanefreight.local
```

```sh
whatweb -a3 app.inlanefreight.local -v
```

>**Q. Which CMS is used on app.inlanefreight.local? (Format: word)**

```sh
whatweb -a3 dev.inlanefreight.local -v
```

## Active Subdomain Enumeration

>**Q. Submit the FQDN of the nameserver for the "inlanefreight.htb" domain as the answer.**

```sh
nslookup -type=NS inlanefreight.htb 10.129.128.199
```

>**Q. Identify how many zones exist on the target nameserver. Submit the number of found zones as the answer.**

```sh
nslookup -type=any inlanefreight.htb 10.129.128.199
```

```sh
dig ANY inlanefreight.htb @10.129.128.199
```

>**Q. Find and submit the contents of the TXT record as the answer.**

```sh
dig @10.129.128.199 NS txt internal.inlanefreight.htb 
```

>**Q. What is the FQDN of the IP address 10.10.34.136?**

```sh
dig @10.129.128.199 NS axfr internal.inlanefreight.htb 
```
```
dig axfr @nsztm1.digi.ninja zonetransfer.me
```

>**Q. What FQDN is assigned to the IP address 10.10.1.5? Submit the FQDN as the answer.**

```sh
dig @10.129.128.199 NS axfr internal.inlanefreight.htb 
```

>**Q. Which IP address is assigned to the "us.inlanefreight.htb" subdomain. Submit the IP address as the answer.**

```sh
dig @10.129.128.199 NS a us.inlanefreight.htb 
```

>**Q. Submit the number of all "A" records from all zones as the answer.**

```sh
dig @10.129.128.199 AXFR a inlanefreight.htb 
```

```sh
dig @10.129.128.199 AXFR a internal.inlanefreight.htb 
```

## Virtual Hosts

>**Q. Enumerate the target and find a vHost that contains flag No. 1. Submit the flag value as your answer (in the format HTB{DATA}).**

```sh
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt -u http://10.129.128.199 -H "HOST: FUZZ.inlanefreight.htb" -fs 10918
```

```sh
nano /etc/hosts
```

```sh
10.129.194.206 ***.inlanefreight.htb ***.inlanefreight.htb ***.inlanefreight.htb ***.inlanefreight.htb
```


```sh
curl -s http://10.129.128.199 -H "Host:***.inlanefreight.htb"
```

>**Q. Enumerate the target and find a vHost that contains flag No. 2. Submit the flag value as your answer (in the format HTB{DATA}).**

```sh
curl -s http://10.129.128.199 -H "Host:***.inlanefreight.htb"
```

>**Q. Enumerate the target and find a vHost that contains flag No. 3. Submit the flag value as your answer (in the format HTB{DATA}).**

```sh
curl -s http://10.129.128.199 -H "Host:***.inlanefreight.htb"
```

>**Q. Enumerate the target and find a vHost that contains flag No. 4. Submit the flag value as your answer (in the format HTB{DATA}).**

```sh
curl -s http://10.129.128.199 -H "Host:***.inlanefreight.htb"
```

>**Q. Find the specific vHost that starts with the letter "d" and submit the flag value as your answer (in the format HTB{DATA}).**

```sh
curl -s http://10.129.128.199 -H "Host:***.inlanefreight.htb"
```

## Information Gathering - Web - Skills Assessment

>**Q. What is the registrar IANA ID number for the githubapp.com domain?**

```sh
whois githubapp.com
```

>**Q. What is the last mailserver returned when querying the MX records for githubapp.com?**

```sh
nslookup -query=MX githubapp.com
```

>**Q. Perform active infrastructure identification against the host https://i.imgur.com. What server name is returned for the host?**

```sh
whatweb -a3 https://i.imgur.com
```
### nikto scan
```
sudo apt update && sudo apt install -y perl
git clone https://github.com/sullo/nikto
cd nikto/program
chmod +x ./nikto.p
nikto -h inlanefreight.com -Tuning b
```

### Creepy Crawlies
```
pip3 install scrapy
wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
unzip ReconSpider.zip
python3 ReconSpider.py http://inlanefreight.com
```
### Automating Recon
```
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon
pip3 install -r requirements.txt
chmod +x ./finalrecon.py
./finalrecon.py --help
./finalrecon.py --headers --whois --url http://inlanefreight.com
```
### Subdomain Bruteforcing
```
dnsenum --enum inlanefreight.com -f  /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r
gobuster vhost -u http://inlanefreight.htb:81 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```
### Web Application Firewalls
```
pip3 install git+https://github.com/EnableSecurity/wafw00f
wafw00f inlanefreight.com
```
### Wwaybackmasin install
```
go install github.com/tomnomnom/waybackurls@latest
cd go/bin
sudo cp waybackurls /usr/bin
waybackurls -h
```
