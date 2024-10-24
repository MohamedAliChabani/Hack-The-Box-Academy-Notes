# <mark class="hltr-pink">Introduction</mark>
## <mark class="hltr-cyan">Active Recon</mark>
In active reconnaissance, the attacker directly interacts with the target system to gather information. This interaction can take various forms:
![[Pasted image 20240731190325.png]]
![[Pasted image 20240731190339.png]]
## <mark class="hltr-cyan">Passive Recon</mark>
Passive reconnaissance involves gathering information about the target `without directly interacting` with it.
![[Pasted image 20240731191459.png]]

---

# <mark class="hltr-pink">WHOIS</mark>

WHOIS is a widely used query and response protocol designed to access databases that store information about registered internet resources. Primarily associated with domain names, WHOIS can also provide details about IP address blocks and autonomous systems. Think of it as a giant phonebook for the internet, letting you look up who owns or is responsible for various online assets.

**WHOIS Records:**
- `Domain Name`: The domain name itself (e.g., example.com)
- `Registrar`: The company where the domain was registered (e.g., GoDaddy, Namecheap)
- `Registrant Contact`: The person or organization that registered the domain.
- `Administrative Contact`: The person responsible for managing the domain.
- `Technical Contact`: The person handling technical issues related to the domain.
- `Creation and Expiration Dates`: When the domain was registered and when it's set to expire.
- `Name Servers`: Servers that translate the domain name into an IP address.

## <mark class="hltr-cyan">Why WHOIS Matters for Web Recon</mark>
It offers valuable insights into the target organisation's digital footprint and potential vulnerabilities:
- Identifying Key Personnel (names, emails, phone numbers ...)
- Discovering Network Infrastructure: Technical details like name servers and IP addresses provide clues about the target's network infrastructure
- Historical Data Analysis

---

# <mark class="hltr-pink">DNS</mark>
## <mark class="hltr-cyan">DNS</mark>
### <mark class="hltr-orange">How DNS Works</mark>
![[Pasted image 20240731195803.png]]

![[Pasted image 20240725164542.png]]

1. <mark class="hltr-green">Your Computer Asks for Directions (DNS Query):</mark> When you enter the domain name, your computer first checks its memory (cache) to see if it remembers the IP address from a previous visit. If not, it reaches out to a DNS resolver, usually provided by your internet service provider (ISP).

2. <mark class="hltr-green">The DNS Resolver Checks its Map (Recursive Lookup)</mark>: The resolver also has a cache, and if it doesn't find the IP address there, it starts a journey through the DNS hierarchy. It begins by asking a root name server, which is like the librarian of the internet.

3. <mark class="hltr-green">Root Name Server Points the Way</mark>: The root server doesn't know the exact address but knows who does – the Top-Level Domain (TLD) name server responsible for the domain's ending (e.g., .com, .org). It points the resolver in the right direction.

4. <mark class="hltr-green">TLD Name Server Narrows It Down</mark>: The TLD name server is like a regional map. It knows which authoritative name server is responsible for the specific domain you're looking for (e.g., `example.com`) and sends the resolver there.

5. <mark class="hltr-green">Authoritative Name Server Delivers the Address</mark>: The authoritative name server is the final stop. It's like the street address of the website you want. It holds the correct IP address and sends it back to the resolver.

6. <mark class="hltr-green">The DNS Resolver Returns the Information</mark>: The resolver receives the IP address and gives it to your computer. It also remembers it for a while (caches it), in case you want to revisit the website soon.

7. <mark class="hltr-green">Your Computer Connects</mark>: Now that your computer knows the IP address, it can connect directly to the web server hosting the website, and you can start browsing.
### <mark class="hltr-orange">Key DNS Concepts</mark>

In the Domain Name System (DNS), a zone is a distinct part of the domain namespace that a specific entity or administrator manages. Think of it as a virtual container for a set of domain names. For example, `example.com` and all its subdomains (like `mail.example.com` or `blog.example.com`) would typically belong to the same DNS zone.

The zone file, a text file residing on a DNS server, defines the resource records within this zone, providing crucial information for translating domain names into IP addresses.

Example:
![[Pasted image 20240731200203.png]]

**DNS RECORDS TYPES**:
![[Pasted image 20240725170035.png]](Further reading: 3 - Footprinting DNS)

## <mark class="hltr-cyan">Digging DNS</mark>
![[Pasted image 20240731202652.png]]
## <mark class="hltr-cyan">Subdomains</mark>
#### <mark class="hltr-orange">Active Subdomain Enumeration</mark>
One method is attempting a `DNS zone transfer`, where a misconfigured server might inadvertently leak a complete list of subdomains. However, due to tightened security measures, <mark class="hltr-red">this is rarely successful.</mark>

A more common active technique is `brute-force enumeration`, which involves systematically testing a list of potential subdomain names against the target domain. Tools like `dnsenum`, `ffuf`, and `gobuster` can automate this process, using wordlists of common subdomain names or custom-generated lists based on specific patterns.

#### <mark class="hltr-orange">Passive Subdomain Enumeration</mark>

This relies on external sources of information to discover subdomains without directly querying the target's DNS servers.

We can look for:
- <mark class="hltr-green">Certificate Transparency (CT)</mark> logs, public repositories of SSL/TLS certificates
- <mark class="hltr-green">search results</mark> using operators (like google's site:)

## <mark class="hltr-cyan">Subdomain Enumeration</mark>
There are many tools that can perform brute-force enumeration, one of them is <mark class="hltr-red">DNSEnum</mark>

The tool offers several key functions:
- `DNS Record Enumeration`
- `Zone Transfer Attempts`
- `Subdomain Brute-Forcing`
- `Google Scraping`
- `Reverse Lookup`
- `WHOIS Lookups`

Enumerating subdomains with dnsenum:
```
dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r
```
- --enum: target domain
- -f wordlist
- enables recursive subdomain brute-forcing, meaning that if `dnsenum` finds a subdomain, it will then try to enumerate subdomains of that subdomain.

## <mark class="hltr-cyan">DNS Zone Transfers</mark>
### <mark class="hltr-orange">What is a Zone Transfer</mark>
A DNS zone transfer is essentially a wholesale copy of all DNS records within a zone (a domain and its subdomains) from one name server to another. This process is essential for maintaining consistency and redundancy across DNS servers.
![[Pasted image 20240731211834.png]]
### <mark class="hltr-orange">The Zone Transfer Vulnerability</mark>
The core issue lies in the access controls governing who can initiate a zone transfer.

The information gleaned from an unauthorised zone transfer can be invaluable to an attacker. It reveals a comprehensive map of the target's DNS infrastructure, including:

- <mark class="hltr-green">Subdomains</mark>: A complete list of subdomains, many of which might not be linked from the main website or easily discoverable through other means. These hidden subdomains could host development servers, staging environments, administrative panels, or other sensitive resources.
- <mark class="hltr-green">IP Addresses</mark>: The IP addresses associated with each subdomain, providing potential targets for further reconnaissance or attacks.
- <mark class="hltr-green">Name Server Records</mark>: Details about the authoritative name servers for the domain, revealing the hosting provider and potential misconfigurations.
### <mark class="hltr-orange">Exploiting Zone Transfers</mark>
This command instructs `dig` to request a full zone transfer (`axfr`) from the DNS server responsible for `zonetransfer.me`. If the server is <mark class="hltr-red">misconfigured</mark> and allows the transfer, you'll receive a complete list of DNS records for the domain, including all subdomains.
```
dig axfr @nsztm1.digi.ninja zonetransfer.me
```

You can also use an IP @ to do this

```
dig axfr @10.129.92.238 inlanefreight.htb zonetransfer.me
```

## <mark class="hltr-cyan">Virtual Hosts</mark>
Virtual Hosts (VHosts): Virtual hosts are configurations within a web server that allow multiple websites or applications to be hosted on a single server

At the core of `virtual hosting` is the ability of web servers to distinguish between multiple websites or applications sharing the same IP address. This is achieved by leveraging the `HTTP Host` header, a piece of information included in every `HTTP` request sent by a web browser.

![[Pasted image 20240801014713.png]]

### <mark class="hltr-orange">Types of Virtual Hosting</mark>

1. <mark class="hltr-green">Name-Based Virtual Hosting</mark>: This method relies solely on the `HTTP Host header` to distinguish between websites. It is the most common and flexible method, as it doesn't require multiple IP addresses. It’s cost-effective, easy to set up, and supports most modern web servers. However, it requires the web server to support name-based `virtual hosting` and can have limitations with certain protocols like `SSL/TLS`.

2. <mark class="hltr-green">IP-Based Virtual Hosting</mark>: This type of hosting assigns a unique IP address to each website hosted on the server. The server determines which website to serve based on the IP address to which the request was sent. It doesn't rely on the `Host header`, can be used with any protocol, and offers better isolation between websites. Still, it requires multiple IP addresses, which can be expensive and less scalable.

3. <mark class="hltr-green">Port-Based Virtual Hosting</mark>: Different websites are associated with different ports on the same IP address. For example, one website might be accessible on port 80, while another is on port 8080. `Port-based virtual hosting` can be used when IP addresses are limited, but it’s not as common or user-friendly as `name-based virtual hosting` and might require users to specify the port number in the URL.

### <mark class="hltr-orange">Virtual Host Discovery Tools</mark>

![[Pasted image 20240801015315.png]]

```gobuster
gobuster vhost -u http://<target_IP_address> -w <wordlist_file> --append-domain inlanefreight.htb
```

(You might want to add the new vhost entry to the /etc/hosts for further information gathering)

<mark class="hltr-red">It's also possible to enumerate subvhosts of a vhost (like a subdomain of a subdomain)</mark>

---

# <mark class="hltr-pink">Fingerprinting</mark>

Fingerprinting focuses on extracting technical details about the technologies powering a website or web application.

Fingerprinting Techniques:
- `Banner Grabbing`
- `Analysing HTTP Headers`
- `Probing for Specific Responses`
- `Analysing Page Content`

## <mark class="hltr-cyan">Banner Grabbing</mark>

```shell-session
curl -I inlanefreight.com
```

## <mark class="hltr-cyan">Wafw00f</mark>

<mark class="hltr-green">Web Application Firewalls</mark> (`WAFs`) are security solutions designed to protect web applications from various attacks.

it's crucial to determine if the target employs a WAF, as it could interfere with our probes or potentially block our requests.

```shell-session
wafw00f inlanefreight.com
```

## <mark class="hltr-cyan">Nikto</mark>

`Nikto` is a powerful open-source web server scanner.

To scan the target using `Nikto`, only running the fingerprinting modules, execute the following command:

```shell-session
nikto -h inlanefreight.com -Tuning b
```

- -h: host
- -Turing b: only run the Software Identification modules.
