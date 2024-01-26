### Proxychains
```
  Proxying Tools
#socks4         127.0.0.1 9050
http 127.0.0.1 8080
```
```
[/htb]$ proxychains curl http://SERVER_IP:PORT

ProxyChains-3.1 (http://proxychains.sf.net)
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Ping IP</title>
    <link rel="stylesheet" href="./style.css">
</head>
...SNIP...
</html>
```
```
[/htb]$ nmap --proxies http://127.0.0.1:8080 SERVER_IP -pPORT -Pn -sC

Starting Nmap 7.91 ( https://nmap.org )
Nmap scan report for SERVER_IP
Host is up (0.11s latency).

PORT      STATE SERVICE
PORT/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 0.49 seconds
```
```
[/htb]$ msfconsole

msf6 > use auxiliary/scanner/http/robots_txt
msf6 auxiliary(scanner/http/robots_txt) > set PROXIES HTTP:127.0.0.1:8080

PROXIES => HTTP:127.0.0.1:8080


msf6 auxiliary(scanner/http/robots_txt) > set RHOST SERVER_IP

RHOST => SERVER_IP


msf6 auxiliary(scanner/http/robots_txt) > set RPORT PORT

RPORT => PORT


msf6 auxiliary(scanner/http/robots_txt) > run

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
### Some extensions worth checking out include, but are not limited to: (BurpSuite, Zap)

```
.NET beautifier	              J2EEScan	        Software Vulnerability Scanner
```
```
Software Version Reporter	    Active Scan++	            Additional Scanner Checks
```
```
AWS Security Checks	          Backslash                 Powered Scanner	Wsdler
```
```
Java Deserialization Scanner	  C02	                    Cloud Storage Tester
```
```
CMS Scanner	                    Error Message Checks	    Detect Dynamic JS
```
```
Headers Analyzer	              HTML5 Auditor	            PHP Object Injection Check
```
```
JavaScript Security	            Retire.JS	                CSP Auditor
```
```
Random IP Address Header	      Autorize	                CSRF Scanner
```
```
JS Link Finder		
```
### ZAP Marketplace
In this tab, we can see the different available add-ons for ZAP. Some add-ons may be in their Release build, meaning that they should be stable to be used, while others are in their ```Beta/Alpha(file upload)``` builds, which means that they may experience some issues in their use. Let's try installing the ```FuzzDB Files``` and ```FuzzDB Offensive``` add-ons, which adds new wordlists to be used in ZAP's fuzzer:

