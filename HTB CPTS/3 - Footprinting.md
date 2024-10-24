
<mark class="hltr-red">Our goal is not to get at the systems but to find all the ways to get there.</mark>
![[Pasted image 20240721100121.png]]

---

## <mark class="hltr-pink">Enumeration Methodology</mark>

The whole enumeration process is divided into three different levels

| Infrastructure-based enumeration | Host-based enumeration | OS-based enumeration |
| -------------------------------- | ---------------------- | -------------------- |

![[Pasted image 20240721101051.png]]Enumaration should be done methodically rather than intuitively

---

### <mark class="hltr-pink">Host Based Enumeration</mark>
#### <mark class="hltr-cyan">FTP</mark>
##### <mark class="hltr-orange">FTP</mark>

| Port   | Role                                                                                                                                                  |
| ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| TCP/21 | the client and server establish a control channel through `TCP port 21`. The client sends commands to the server, and the server returns status codes |
| TCP/20 | data channel (transmission / reception)                                                                                                               |

- FTP is a clear-text protocol
- anonymous FTP allows any user to upload or download files via FTP without using a password
##### <mark class="hltr-orange">TFTP</mark>
- Trivial File Transfer Protocol (`TFTP`) is simpler than FTP
- TFTP does not provide user authentication
- TFTP uses UDP
- file access is solely reliant on the r/w permissions in the OS

##### <mark class="hltr-orange">Default Configuration</mark>
The default configuration of vsFTPd can be found in `/etc/vsftpd.conf`

In addition, there is a file called `/etc/ftpusers` that serves as a blacklist (any user found in that file cannot login to the ftp service)

##### <mark class="hltr-orange">Dangerous Settings</mark>
 ![[Pasted image 20240721110916.png]]

##### <mark class="hltr-orange">Downloading all files</mark>
```
wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136

```
##### <mark class="hltr-orange">Interacting with an FTP server that runs TLS/SSL encryption</mark>
```
openssl s_client -connect 10.129.14.136:21 -starttls ftp
```

#### <mark class="hltr-cyan">SMB</mark>
##### <mark class="hltr-orange">Connecting to a share (anonymously)</mark>
- listing shares
```
smbclient -N -L //10.129.14.128
```
- connecting to a share
```
smbclient //10.129.14.128/notes
```
##### <mark class="hltr-orange">Footprinting the service</mark>
- Nmap
```
sudo nmap 10.129.14.128 -sV -sC -p139,445
```
- RPCclient
```
rpcclient -U "" 10.129.14.128
```
![[Pasted image 20240725043117.png]]
- RPCclient user enumeration
![[Pasted image 20240725043422.png]]
- Brute Forcing User RIDs
```
for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
```

- Impacket - Samrdump.py 
[samrdumpy.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/samrdump.py)
```
samrdump.py 10.129.14.128
```
-  Enum4Linux-ng - Enumeration
```
enum4linux-ng.py 10.129.14.128 -A
```

#### <mark class="hltr-cyan">NFS</mark>
Port 111 and 2049
default config is found in `/etc/exports`
##### <mark class="hltr-orange">Dangerous settings</mark>
![[Pasted image 20240725055046.png]]
##### <mark class="hltr-orange">Footprinting the service</mark>
- Nmap
```
sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049
```
The `rpcinfo` NSE script retrieves a list of all currently running RPC services, their names and descriptions, and the ports they use.

- Show Available NFS Shares
```
showmount -e 10.129.14.128
```

- Mounting NFS Share
```
mkdir target-NFS
sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
```

#### <mark class="hltr-cyan">DNS</mark>

![[Pasted image 20240725164542.png]]
Reference: [DNS Explained in details](https://www.youtube.com/watch?v=HnUDtycXSNE)

An entry in a DNS nameserver, also known as a DNS record, contains specific information about a domain and its associated services. Each entry in a DNS nameserver is formatted in a way that helps DNS resolvers understand how to handle requests for that domain. Here’s a breakdown of what an entry typically looks like:

```
<NAME> <TTL> <CLASS> <TYPE> <DATA>
```

examples:
- `example.com. 3600 IN A 192.0.2.1`
- `example.com. 3600 IN AAAA 2001:db8::1`
- `www.example.com. 3600 IN CNAME example.com.`
- `example.com. 3600 IN MX 10 mail.example.com.`
- `example.com. 3600 IN NS ns1.example.com.`

![[Pasted image 20240725170035.png]]
##### <mark class="hltr-orange">Footprinting the service</mark>
- DIG - NS Query
the DNS server can be queried as to which other name servers are known.

```
dig ns inlanefreight.htb @10.129.14.128
```

- DIG - ANY Query
We can use the option `ANY` to view all available records. This will cause the server to show us all available entries that it is willing to disclose. It is important to note that <mark class="hltr-red">not all entries from the zones will be shown</mark>.

```
dig any inlanefreight.htb @10.129.14.128
```

- DIG - AXFR Zone Transfer
Zone transfer refers to the transfer of zones to another server in DNS, which generally happens over TCP port 53. This procedure is abbreviated `Asynchronous Full Transfer Zone` (`AXFR`).
```
dig axfr inlanefreight.htb @10.129.14.128
```

- DIG - AXFR Zone Transfer - Internal
```
dig axfr internal.inlanefreight.htb @10.129.14.128
```

- Subdomain Brute Forcing
```
for sub in $(cat /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
```

or using a tool like [DNSEnum](https://github.com/fwaeytens/dnsenum)
```
dnsenum --dnsserver 10.129.11.220  --enum -p 0 -s 0 -o subdomains.txt -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```

(You might also use `/usr/share/wordlists/seclists/Discovery/DNS/fierce-hostlist.txt`)

#### <mark class="hltr-cyan">SMTP</mark>
SMTP runs on port 25 (TCP)
##### <mark class="hltr-orange">SMTP commands</mark>
![[Pasted image 20240725204115.png]]
- connecting to the smtp server
```
telnet 10.129.14.128 25
```

❗: Sometimes we may have to work through a web proxy. We can also make this web proxy connect to the SMTP server. The command that we would send would then look something like this: `CONNECT 10.129.14.128:25 HTTP/1.0`

##### <mark class="hltr-orange">Footprinting</mark>
- Nmap - Open Relay
```
sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v
```
- Enumerating users
There is a metasploit module for this
```
search scanner/smtp/smtp_enum
```

#### <mark class="hltr-cyan">IMAP / POP3</mark>
IMAP (TCP 143)
POP3 (TCP 110)

##### <mark class="hltr-orange">IMAP Commands</mark>
![[Pasted image 20240727033900.png]]
<mark class="hltr-red">(Chatgpt is really helpful for writing imap commands)</mark>

##### <mark class="hltr-orange">POP3 Commands</mark>
![[Pasted image 20240727034005.png]]

##### <mark class="hltr-orange">Footprinting the service</mark>
- Nmap
```
sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC
```
- curl
```
curl -k 'imaps://10.129.14.128' --user user:p4ssw0rd
```
- OpenSSL - TLS Encrypted Interaction POP3
```
openssl s_client -connect 10.129.14.128:pop3s
```
- OpenSSL - TLS Encrypted Interaction IMAP
```
openssl s_client -connect 10.129.14.128:imaps
```

#### <mark class="hltr-cyan">SNMP</mark>
SNMP (UDP 161)
##### <mark class="hltr-orange">SNMP Versions</mark>

| Version | Description                                                                                                          |
| ------- | -------------------------------------------------------------------------------------------------------------------- |
| SNMPv1  | - no built-in authentication<br>- does not support encryption                                                        |
| SNMPv2c | - does not use passwords, it uses community<br>strings as an authentication method<br>- does not support encryption  |
| SNMPv3  | - authentication using username and password<br>- supports encryption<br>- complex compared to the previous versions |

##### <mark class="hltr-orange">Footprinting</mark>
Tools:
- snmpwalk -> query the OIDs with their information (once we know the snmp version that is running on the server)
```
snmpwalk -v2c -c public 10.129.14.128
```


- onesixtyone -> brute-force the names of the community strings
```
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 10.129.14.128
```
![[Pasted image 20240729121808.png]]
In this case `backup` is the community string

- braa
Once we know a community string, we can use it with [braa](https://github.com/mteg/braa) to brute-force the individual OIDs and enumerate the information behind them.

#### <mark class="hltr-cyan">mysql</mark>
##### <mark class="hltr-orange">Footprinting</mark>
- scanning
```
sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*
```
- interacting with the database
![[Pasted image 20240727103213.png]]

The most important databases for the MySQL server are the `system schema` (<mark class="hltr-green">sys</mark>) and `information schema` (<mark class="hltr-green">information_schema</mark>).
The system schema contains tables, information, and metadata necessary for management.

```
use sys;
show tables;
select host, unique_users from host_summary;
```

#### <mark class="hltr-cyan">MSSQL</mark>
mssql (TCP 1433)
##### <mark class="hltr-orange">MSSQL Databases</mark>
![[Pasted image 20240727113837.png]]
##### <mark class="hltr-orange">Footprinting</mark>
- Nmap
```
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248
```
- MSSQL Ping in Metasploit
```
use auxiliary/scanner/mssql/mssql_ping
set RHOSTS 10.129.201.248
run
```

- Connecting with Mssqlclient.py
```
python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth
```

- Connecting with sqsh
```shell-session
sqsh -S 10.129.20.13 -U username -P Password123
```

- Connecting from windows host
```cmd-session
C:> sqlcmd -S 10.129.20.13 -U username -P Password123
```

MSSQL uses <mark class="hltr-red">T-SQL</mark> so the syntax is different from mysql
here's how to list all available databases (you should compare the results with the default databases list shown above)

```
select name from sys.databases
```

#### <mark class="hltr-cyan">Oracle TNS</mark>
The `Oracle Transparent Network Substrate` (`TNS`) server is a communication protocol that facilitates communication between Oracle databases and applications over networks

By default, the listener listens for incoming connections on the `TCP/1521` port

##### <mark class="hltr-orange">Footprinting</mark>
- Nmap
```
sudo nmap -p1521 -sV 10.129.204.235 --open
```
A System Identifier (`SID`) is a unique name that identifies a particular database instance

- Nmap - SID Bruteforcing
```
sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute
```

- ODAT
```
odat all -s 10.129.204.235
```

- SQLplus - Log In
```
sqlplus scott/tiger@10.129.204.235/XE
```
- Oracle RDBMS - Interaction
```
select table_name from all_tables;
select * from user_role_privs;
```

- Oracle RDBMS - Database Enumeration
This is possible if the user has sysdba privilege
```shell-session
sqlplus scott/tiger@10.129.204.235/XE as sysdba
select * from user_role_privs;
```

- Oracle RDBMS - Extract Password Hashes
```
select name, password from sys.user$;
```

- Oracle RDBMS - File Upload (WEB)
On Windows:
```
echo "Oracle File Upload Test" > testing.txt
./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
```

On Linux:
```
echo "Oracle File Upload Test" > testing.txt
./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile /var/www/html testing.txt ./testing.txt
```

Finally, we can test if the file upload approach worked with `curl`. Therefore, we will use a `GET http://<IP>` request, or we can visit via browser.

```shell-session
curl -X GET http://10.129.204.235/testing.txt
```

if this worked then we can upload a web shell to the target

#### <mark class="hltr-cyan">IPMI</mark>
[Intelligent Platform Management Interface](https://www.thomas-krenn.com/en/wiki/IPMI_Basics) IPMI (UDP 623)
IPMI provides sysadmins with the ability to manage and monitor systems even if they are powered off or in an unresponsive state. It operates using a direct network connection to the system's hardware and does not require access to the operating system via a login shell

##### <mark class="hltr-orange">Baseboard Management Controller (BMC)</mark>
- A micro-controller and essential component of an IPMI.
- The most common BMCs we often see during internal penetration tests are HP iLO, Dell DRAC, and Supermicro IPMI.
- If we can access a BMC during an assessment, we would gain full access to the host motherboard and be able to monitor, reboot, power off, or even reinstall the host operating system.
- Gaining access to a BMC is nearly equivalent to physical access to a system.
- Many BMCs expose a web-based management console.

##### <mark class="hltr-orange">Footprinting</mark>
- Nmap
```
sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local
```
- Metasploit Version Scan
```
use auxiliary/scanner/ipmi/ipmi_version
set rhosts 10.129.42.195
run
```
- Default passwords
![[Pasted image 20240728184032.png]]
When dealing with BMCs, these default passwords may gain us access to the web console or even command line access via SSH or Telnet.

- Dangerous settings
If default credentials do not work to access a BMC, we can turn to a [flaw](http://fish2.com/ipmi/remote-pw-cracking.html) in the RAKP protocol in <mark class="hltr-red">IPMI 2.0</mark>. During the authentication process, the server sends a salted SHA1 or MD5 hash of the user's password to the client before authentication takes place. This can be leveraged to obtain the password hash for ANY valid user account on the BMC.

These password hashes can then be cracked offline using a dictionary attack using `Hashcat` mode `7300`. In the event of an HP iLO using a factory default password, we can use this Hashcat mask attack command `hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u` which tries all combinations of upper case letters and numbers for an eight-character password.

- Metasploit Dumping Hashes
```shell-session
use auxiliary/scanner/ipmi/ipmi_dumphashes
set OUTPUT_JOHN_FILE hashes.john
set rhosts 10.129.42.195
run
```

- cracking hashes
once we retrieve the hashes returned by metasploit we can crack those using john
```
/usr/sbin/john \  john \
    --fork=15 \
    --wordlist=/usr/share/wordlists/rockyou.txt \
    --format=rakp \
    --session=ipmi \
    hashes.john
```

#### <mark class="hltr-cyan">SSH</mark>
ssh (TCP 22)
##### <mark class="hltr-orange">Footprinting</mark>
```
ssh-audit.py 10.129.14.132
```

Allowing password authentication allows us to brute-force a known username for possible passwords

#### <mark class="hltr-cyan">Rsync</mark>
[Rsync](https://linux.die.net/man/1/rsync) is a fast and efficient tool for locally and remotely copying files. (By default, it uses port TCP `873`)

Rsync can be abused, most notably by listing the contents of a shared folder on a target server and retrieving files. This can sometimes be done without authentication. Other times we will need credentials. If you find credentials during a pentest and run into Rsync on an internal (or external) host, it is always worth checking for password re-use as you may be able to pull down some sensitive files that could be used to gain remote access to the target.

##### <mark class="hltr-orange">Probing for Accessible Shares</mark>
```
nc -nv 127.0.0.1 873
```
then
```
#list
```
We do this to list shares
##### <mark class="hltr-orange">Enumerating an Open Share</mark>
```
rsync -av --list-only rsync://127.0.0.1/dev
```

If Rsync is configured to use SSH to transfer files, we could modify our commands to include the `-e ssh` flag, or `-e "ssh -p2222"` if a non-standard port is in use for SSH

#### <mark class="hltr-cyan">R-Services</mark>
- R-Services are a suite of services hosted to enable remote access or issue commands between Unix hosts over TCP/IP.
- `r-services` were the de facto standard for remote access between Unix operating systems until they were replaced by the Secure Shell (`SSH`) protocols and commands due to inherent security flaws built into them
- Much like `telnet`, r-services transmit information from client to server(and vice versa.) over the network in an unencrypted format, making it possible for attackers to intercept network traffic (passwords, login information, etc.) by performing man-in-the-middle (`MITM`) attacks.

`R-services` span across the ports `512`, `513`, and `514` and are only accessible through a suite of programs known as `r-commands`.

- R-Services Commands
![[Pasted image 20240728193938.png]]

- Scanning for R-Services
```shell-session
sudo nmap -sV -p 512,513,514 10.0.17.2
```

- Logging in Using Rlogin
```shell-session
rlogin 10.0.17.2 -l htb-student
```

- Listing Authenticated Users Using Rwho
```
rwho
```
-  Listing Authenticated Users Using Rusers
This will give us more information
```
rusers -al 10.0.17.5
```

#### <mark class="hltr-cyan">RDP</mark>
The [Remote Desktop Protocol](https://docs.microsoft.com/en-us/troubleshoot/windows-server/remote/understanding-remote-desktop-protocol) (`RDP`) is a protocol developed by Microsoft.

typically utilizing TCP port 3389 as the transport protocol. However, the connectionless UDP protocol can use port 3389 also for remote administration.

##### <mark class="hltr-orange">Footprinting</mark>
- Nmap
```
nmap -sV -sC 10.129.201.248 -p3389 --script rdp*
```
- Initiate an RDP Session
```
xfreerdp /u:cry0l1t3 /p:"P455w0rd!" /v:10.129.201.248
```

#### <mark class="hltr-cyan">WinRM</mark>
The Windows Remote Management (`WinRM`) is a simple Windows integrated remote management protocol based on the command line.
WinRM uses the Simple Object Access Protocol (`SOAP`) to establish connections to remote hosts and their applications.

WinRM relies on `TCP` ports `5985` and `5986` for communication, with the last port `5986 using HTTPS`
##### <mark class="hltr-orange">Footprinting</mark>
- Nmap
```
nmap -sV -sC 10.129.201.248 -p5985,5986 --disable-arp-ping -n
```
- Interacting with WinRM
```
evil-winrm -i 10.129.201.248 -u Cry0l1t3 -p P455w0rD!
```

#### <mark class="hltr-cyan">WMI</mark>

- Windows Management Instrumentation (`WMI`) allows read and write access to almost all settings on Windows systems. Understandably, this makes it the most critical interface in the Windows environment.
- WMI is typically accessed via PowerShell, VBScript, or the Windows Management Instrumentation Console (`WMIC`). WMI is not a single program but consists of several programs and various databases, also known as repositories.

##### <mark class="hltr-orange">Footprinting the Service</mark>
The initialization of the WMI communication always takes place on `TCP` port `135`, and after the successful establishment of the connection, the communication is moved to a random port. For example, the program [wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py) from the Impacket toolkit can be used for this.

```
wmiexec.py Cry0l1t3:"P455w0rD!"@10.129.201.248 "hostname"
```
