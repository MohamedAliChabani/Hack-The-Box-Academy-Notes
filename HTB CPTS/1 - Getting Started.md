## Service Scanning
- Grabbing http headers
```
curl -I $IP $PORT
```

- SMB
	- Listing Shares
	``` smbclient -N -L \\\\$IP ```
	- Connecting to a share
	``` smbclient -U $user \\\\$ip\\$share```
	- `smbclient //server/share --user username`
	

- FTP anonymous login
```
ftp ftp://$ip
```
