### Brute Forcing Passwords
```
[/htb]$ grep '[[:upper:]]' rockyou.txt | grep '[[:lower:]]' | grep -E '^.{8,12}$' | wc -l
```
```
[/htb]$ grep '[[:upper:]]' /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt | grep '[[:lower:]]' | grep '[[:digit:]]' | grep -E '.{10}' > custom_wordlist.txt
```
# Useful Links

[SCADA HMI Username/Password](https://www.192-168-1-1-ip.co/router/advantech/advantech-webaccess-browser-based-hmi-and-scada-software/11215/)

[SecLists](https://github.com/danielmiessler/SecLists)

[EpochConverter](https://www.epochconverter.com/)

[CyberChef](https://gchq.github.io/)

[List_of_file_signatures](https://en.wikipedia.org/wiki/List_of_file_signatures) 

[Decodify](https://github.com/s0md3v/Decodify)
