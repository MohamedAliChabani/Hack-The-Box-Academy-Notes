## <mark class="hltr-pink">Introduction to Nmap</mark>

There are many scanning types that can be done with nmap
```
SCAN TECHNIQUES:
  -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
  -sU: UDP Scan
  -sN/sF/sX: TCP Null, FIN, and Xmas scans
  --scanflags <flags>: Customize TCP scan flags
  -sI <zombie host[:probeport]>: Idle scan
  -sY/sZ: SCTP INIT/COOKIE-ECHO scans
  -sO: IP protocol scan
  -b <FTP relay host>: FTP bounce scan
```

The TCP SYN scan is the default:
*<mark class="hltr-yellow">Quick overview</mark>* 
Our machine first sends a TCP SYN segment

| Response | Explanation                                                                                                  |
| -------- | ------------------------------------------------------------------------------------------------------------ |
| SYN-ACK  | If our target sends an `SYN-ACK` flagged packet back to the scanned port, Nmap detects that the port is open |
| RST      | If the packet receives an `RST` flag, it is an indicator that the port is `closed`                           |
| nothing  | If Nmap does not receive a packet back, it will display it as `filtered`                                     |

---

## <mark class="hltr-pink">Host Discovery</mark>
### <mark class="hltr-cyan">Scan network range</mark>
Discovering online systems (ping sweep)
```
sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5
```
### <mark class="hltr-cyan">Scan a list of IPs</mark>
In case we have a list of IP addresses in a file we can scan those by giving the file to nmap
```
sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5
```

---

## <mark class="hltr-pink">Host and Port Scanning</mark>
### <mark class="hltr-cyan">Port states</mark>
![[Pasted image 20240721030658.png]]
### <mark class="hltr-cyan">scanning the top 100 ports</mark>

```
sudo nmap 10.129.2.28 --top-ports=100
```
or
```
sudo nmap -F 10.129.2.28
```
### <mark class="hltr-cyan">scanning all ports</mark>
```
sudo nmap 10.129.2.28 -p-
```

### <mark class="hltr-cyan">scanning a port range</mark>
```
sudo nmap 10.129.2.28 -p22-445
```

### <mark class="hltr-cyan">UDP scan</mark>
```
sudo nmap -F -sU 10.129.2.28
```

---

## <mark class="hltr-pink">Service enumeration</mark>
### Banner grabbing
```
nc -nv 10.129.2.28 25
```

---

## <mark class="hltr-pink">Scripting engine</mark>
![[Pasted image 20240721041835.png]]

---

## <mark class="hltr-pink">Firewall and IDS/IPS Evasion</mark>
When a port is shown as filtered, it can have several reasons. In most cases, firewalls have certain rules set to handle specific connections.

### <mark class="hltr-cyan">Determine Firewalls and Their Rules ACK scan</mark>


Firewalls and IDS/IPS systems typically block incoming SYN packets making the usual SYN (-sS) and connect (-sT) scans ineffective.
Thus using an **ACK scan** (-sA) might be a good idea because the firewall cannot determine whether the connection was first established from the external network or the internal network.

(You should also enable the --packet-trace option, read the SA R S or A in that section)

| R   | RESET   |
| --- | ------- |
| SA  | SYN-ACK |
| S   | SYN     |
| A   | ACK     |
### <mark class="hltr-cyan">Scan by using different source ip</mark>
```
sudo nmap 10.129.2.28 -n -Pn -p445 -S 10.129.2.200 -e tun0
```

### <mark class="hltr-cyan">DNS Proxying</mark>
#### SYN-Scan from DNS port
If a port comes up as `filtered`, you can try to scan it using 53 (DNS) as a source port number
```
sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53
```

If it's now shown as open then you can connect (once again using 53 as a source port number)
```
nc -nv --source-port 53 10.129.2.28 50000
```

---

## <mark class="hltr-pink">References</mark>
- [Nmap scan types](https://nmap.org/book/man-port-scanning-techniques.html)
- [nmap docs](https://www.nmap.org) 