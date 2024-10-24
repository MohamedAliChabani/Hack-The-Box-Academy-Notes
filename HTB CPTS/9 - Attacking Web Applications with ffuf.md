# <mark class="hltr-pink">Basic Fuzzing</mark>
## <mark class="hltr-cyan">Directory fuzzing</mark>

```shell-session
ffuf -ic -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ
```

-ic: ignore wordlist comments


## <mark class="hltr-cyan">Page Fuzzing</mark>
### <mark class="hltr-orange">Extension Fuzzing</mark>

We must find out what types of pages the website uses, like `.html`, `.aspx`, `.php`, or something else.
There is one file we can always find in most websites, which is `index.*`, so we will use it as our file and fuzz extensions on it.
```shell-session
ffuf -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ
```

### <mark class="hltr-orange">Page Fuzzing</mark>

We will now use the same concept of keywords we've been using with `ffuf`, use `.php` as the extension, place our `FUZZ` keyword where the filename should be, and use the same wordlist we used for fuzzing directories:

(Assuming the servers uses .php files)

```shell-session
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php
```

## <mark class="hltr-cyan">Recursive Fuzzing</mark>

So far, we have been fuzzing for directories, then going under these directories, and then fuzzing for files. However, if we had dozens of directories, each with their own subdirectories and files, this would take a very long time to complete. To be able to automate this, we will utilize what is known as `recursive fuzzing`.

When we scan recursively, it automatically starts another scan under any newly identified directories that may have on their pages until it has fuzzed the main website and all of its subdirectories.

```shell-session
ffuf -ic -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v

```

---

# <mark class="hltr-pink">Domain Fuzzing</mark>

## <mark class="hltr-cyan">Subdomain Fuzzing</mark>

```shell-session
ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.academy.htb/
```

## <mark class="hltr-cyan">Vhost Fuzzing</mark>

### <mark class="hltr-orange">Vhost vs Subdomain</mark>

The key difference between VHosts and sub-domains is that a VHost is basically a 'sub-domain' served on the same server and has the same IP, such that a single IP could be serving two or more different websites.

### <mark class="hltr-orange">Fuzzing</mark>

To scan for VHosts, without manually adding the entire wordlist to our `/etc/hosts`, we will be fuzzing HTTP headers, specifically the `Host:` header. To do that, we can use the `-H` flag to specify a header and will use the `FUZZ` keyword within it, as follows:

```shell-session
ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'
```

![[Pasted image 20241007202550.png]]

We see that all words in the wordlist are returning `200 OK`! This is expected, as we are simply changing the header while visiting `http://academy.htb:PORT/`. So, we know that we will always get `200 OK`. However, if the VHost does exist and we send a correct one in the header, we should get a <mark class="hltr-red">different response size</mark>, as in that case, we would be getting the page from that VHosts, which is likely to show a different page.

### <mark class="hltr-orange">Filtering Results</mark>

`Ffuf` provides the option to match or filter out a specific HTTP code, response size, or amount of words. We can see that with `ffuf -h`:

![[Pasted image 20241008112740.png]]

(To open the results in a web browser you should add every vhost to the `/etc/hosts` file)

---

# <mark class="hltr-pink">Parameter Fuzzing</mark>

## <mark class="hltr-cyan">Parameter Fuzzing - GET</mark>

If we run a recursive `ffuf` scan on `admin.academy.htb`, we should find `http://admin.academy.htb:PORT/admin/admin.php`. If we try accessing this page, we see the following:

![[Pasted image 20241008113736.png]]

That indicates that there must be something that identifies users to verify whether they have access to read the `flag`. We did not login, nor do we have any cookie that can be verified at the backend. So, perhaps there is a key that we can pass to the page to read the `flag`. Such keys would usually be passed as a `parameter`, using either a `GET` or a `POST` HTTP request.

Similarly to how we have been fuzzing various parts of a website, we will use `ffuf` to enumerate parameters. Let us first start with fuzzing for `GET` requests, which are usually passed right after the URL, with a `?` symbol, like:

```shell-session
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx
```

## <mark class="hltr-cyan">Parameter Fuzzing POST</mark>

To fuzz the `data` field with `ffuf`, we can use the `-d` flag, as we saw previously in the output of `ffuf -h`. We also have to add `-X POST` to send `POST` requests.

❗: Tip: In PHP, "POST" data "<mark class="hltr-red">Content-Type</mark>" can only accept "<mark class="hltr-red">application/x-www-form-urlencoded</mark>". So, we can set that in "ffuf" with "-H 'Content-Type: application/x-www-form-urlencoded'".

```shell-session
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```


## <mark class="hltr-cyan">Value Fuzzing</mark>

we can guess that the `id` parameter can accept a number input of some sort. These ids can be in a custom format, or can be sequential, like from 1-1000 or 1-1000000, and so on. We'll start with a wordlist containing all numbers from 1-1000.

```shell-session
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

```shell-session
ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```

