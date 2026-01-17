# Host Discovery

```
Scan Network Range
  Host Discovery
mdmithu@htb[/htb]$ sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5

10.129.2.4
10.129.2.10
10.129.2.11
10.129.2.18
10.129.2.19
10.129.2.20
10.129.2.28
```
```
  Host Discovery
mdmithu@htb[/htb]$ cat hosts.lst

10.129.2.4
10.129.2.10
10.129.2.11
10.129.2.18
10.129.2.19
10.129.2.20
10.129.2.28
```
```
Host Discovery
mdmithu@htb[/htb]$ sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5

10.129.2.18
10.129.2.19
10.129.2.20
```
```
Host Discovery
mdmithu@htb[/htb]$ sudo nmap -sn -oA tnet 10.129.2.18 10.129.2.19 10.129.2.20| grep for | cut -d" " -f5

10.129.2.18
10.129.2.19
10.129.2.20
```
```
Host Discovery
mdmithu@htb[/htb]$ sudo nmap -sn -oA tnet 10.129.2.18-20| grep for | cut -d" " -f5

10.129.2.18
10.129.2.19
```
```
Host Discovery
mdmithu@htb[/htb]$ sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace 

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-15 00:08 CEST
SENT (0.0074s) ARP who-has 10.129.2.18 tell 10.10.14.2
RCVD (0.0309s) ARP reply 10.129.2.18 is-at DE:AD:00:00:BE:EF
Nmap scan report for 10.129.2.18
Host is up (0.023s latency).
MAC Address: DE:AD:00:00:BE:EF
Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds
```
```
Host Discovery
mdmithu@htb[/htb]$ sudo nmap 10.129.2.18 -sn -oA host -PE --reason 

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-15 00:10 CEST
SENT (0.0074s) ARP who-has 10.129.2.18 tell 10.10.14.2
RCVD (0.0309s) ARP reply 10.129.2.18 is-at DE:AD:00:00:BE:EF
Nmap scan report for 10.129.2.18
Host is up, received arp-response (0.028s latency).
MAC Address: DE:AD:00:00:BE:EF
Nmap done: 1 IP address (1 host up) scanned in 0.03 seconds
```
```
Host Discovery
mdmithu@htb[/htb]$ sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace --disable-arp-ping 

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-15 00:12 CEST
SENT (0.0107s) ICMP [10.10.14.2 > 10.129.2.18 Echo request (type=8/code=0) id=13607 seq=0] IP [ttl=255 id=23541 iplen=28 ]
RCVD (0.0152s) ICMP [10.129.2.18 > 10.10.14.2 Echo reply (type=0/code=0) id=13607 seq=0] IP [ttl=128 id=40622 iplen=28 ]
Nmap scan report for 10.129.2.18
Host is up (0.086s latency).
MAC Address: DE:AD:00:00:BE:EF
Nmap done: 1 IP address (1 host up) scanned in 0.11 seconds
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
```
1
```
```
2
```
