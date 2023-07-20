# [HTB] JavaScript Deobfuscation

## HTTP Requests

>**Q.  Try applying what you learned in this section by sending a 'POST' request to '/serial.php'. What is the response you get?**

```bash
curl -s http://83.136.250.34:34154/serial.php -X POST
```

>**Q. Try to Analyze the deobfuscated JavaScript code, and understand its main functionality. Once you do, try to replicate what it's doing to get a secret key. What is the key?**

```bash
curl -s http://94.237.62.6:35342/keys.php -X POST
```

>**Q. Once you have the secret key, try to decide it's encoding method, and decode it. Then send a 'POST' request to the same previous page with the decoded key as "key=DECODED_KEY". What is the flag you got?**

```bash
echo 4150495f70336e5f37333537316e3 | xxd -p -r

curl http://94.237.62.6:35342/keys.php -X POST -d "key=API_p3n_73571n6_15_fun"
```
