# [HTB] Command Injections

## WHOIS

>**Q. Perform a WHOIS lookup against the paypal.com domain. What is the registrant Internet Assigned Numbers Authority (IANA) ID number?**

```sh
whois paypal.com
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

