# [HTB_Academy] Getting Started

## Basic Tools

>**Q. Apply what you learned in this section to grab the banner of the above server and submit it as the answer.**

## Service Scanning

>**Q. Perform a Nmap scan of the target. What is the version of the service from the Nmap scan running on port 8080?**

>**Q. Perform an Nmap scan of the target and identify the non-default port that the telnet service is running on.**

>**Q. List the SMB shares available on the target host. Connect to the available share as the bob user. Once connected, access the folder called 'flag' and submit the contents of the flag.txt file.**

## Web Enumeration

>**Q. Try running some of the web enumeration techniques you learned in this section on the server above, and use the info you get to get the flag.**


## Public Exploits

>**Q. Try to identify the services running on the server above, and then try to search to find public exploits to exploit them. Once you do, try to get the content of the '/flag.txt' file. (note: the web server may take a few seconds to start)**



## Privilege Escalation

>**Q. SSH into the server above with the provided credentials, and use the '-p xxxxxx' to specify the port shown above. Once you login, try to find a way to move to 'user2', to get the flag in '/home/user2/flag.txt'.**

>**Q. Once you gain access to 'user2', try to find a way to escalate your privileges to root, to get the flag in '/root/flag.txt'.**


## Nibbles - Enumeration

>**Q. Run an nmap script scan on the target. What is the Apache version running on the server? (answer format: X.X.XX)**

nmap -sV -A 10.129.13.195 

## Nibbles - Initial Foothold

>**Q. Gain a foothold on the target and submit the user.txt flag**


## Nibbles - Privilege Escalation

>**Q. Escalate privileges and submit the root.txt flag.**



## Knowledge Check

>**Q. Spawn the target, gain a foothold and submit the contents of the user.txt flag.**

>**Q. After obtaining a foothold on the target, escalate privileges to root and submit the contents of the root.txt flag.**



