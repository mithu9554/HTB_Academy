# [HTB] Command Injections

## Detection

>**Q. Try adding any of the injection operators after the ip in IP field. What did the error message say (in English)?**

## Injecting Commands

>**Q. Review the HTML source code of the page to find where the front-end input validation is happening. On which line number is it?**

## Other Injection Operators

>**Q. Try using the remaining three injection operators (new-line, &, |), and see how each works and how the output differs. Which of them only shows the output of the injected command?**

## Identifying Filters

>**Q. Try all other injection operators to see if any of them is not blacklisted. Which of (new-line, &, |) is not blacklisted by the web application?**

## Bypassing Space Filters

>**Q. Use what you learned in this section to execute the command 'ls -la'. What is the size of the 'index.php' file?**

## Bypassing Other Blacklisted Characters

>**Q. Use what you learned in this section to find name of the user in the '/home' folder. What user did you find?**

## Bypassing Blacklisted Commands

>**Q. Use what you learned in this section find the content of flag.txt in the home folder of the user you previously found.**

## Advanced Command Obfuscation

>**Q. Find the output of the following command using one of the techniques you learned in this section: find /usr/share/ | grep root | grep mysql | tail -n 1**

## Skills Assessment

>**Q. What is the content of '/flag.txt'?**
