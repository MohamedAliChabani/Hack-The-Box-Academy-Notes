# <mark class="hltr-pink">Hydra</mark>

## <mark class="hltr-cyan">Hydra</mark>

Syntax:
```shell-session
hydra [login_options] [password_options] [attack_options] [service_options]
```

Example (without example):
```
hydra -l admin -P /path/to/password_list.txt 192.168.1.100 ftp
```

Example (with example):
```
hydra http-get://example.com/login.php -m "POST:user=^USER^&pass=^PASS^"
```

### <mark class="hltr-orange">Brute-Forcing a Web Login Form</mark>

Suppose you are tasked with brute-forcing a login form on a web application at `www.example.com`. You know the username is "admin," and the form parameters for the login are `user=^USER^&pass=^PASS^`. To perform this attack, use the following Hydra command:

```shell-session
hydra -l admin -P passwords.txt www.example.com http-post-form "/login:user=^USER^&pass=^PASS^:S=302"
```

This command instructs Hydra to:

- Use the <mark class="hltr-green">username</mark> "admin".
- Use the list of <mark class="hltr-green">passwords</mark> from the `passwords.txt` file.
- Target the login form at <mark class="hltr-green">/login</mark> on `www.example.com`
- Employ the <mark class="hltr-green">http-post-form</mark> module with the specified form parameters.
- Look for a successful login indicated by the HTTP <mark class="hltr-green">status code 302</mark>.

### <mark class="hltr-orange">Advanced RDP Brute-Forcing</mark>

Now, imagine you're testing a Remote Desktop Protocol (RDP) service on a server with IP `192.168.1.100`. You suspect the username is "administrator," and that the password consists of 6 to 8 characters, including lowercase letters, uppercase letters, and numbers. To carry out this precise attack, use the following Hydra command:

```shell-session
hydra -l administrator -x 6:8:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 192.168.1.100 rdp
```

## <mark class="hltr-cyan">Basic HTTP Authentication</mark>
### <mark class="hltr-orange">Basic HTTP Authentication</mark>

In essence, Basic Auth is a challenge-response protocol where a web server demands user credentials before granting access to protected resources. The process begins when a user attempts to access a restricted area. The server responds with a `401 Unauthorized` status and a `WWW-Authenticate` header prompting the user's browser to present a login dialog.

Once the user provides their username and password, the browser concatenates them into a single string, separated by a colon. This string is then encoded using Base64 and included in the `Authorization` header of subsequent requests, following the format `Basic <encoded_credentials>`. The server decodes the credentials, verifies them against its database, and grants or denies access accordingly.

```http
GET /protected_resource HTTP/1.1
Host: www.example.com
Authorization: Basic YWxpY2U6c2VjcmV0MTIz
```

### <mark class="hltr-orange">Exploiting Basic Auth with Hydra</mark>

```shell-session
hydra -l basic-auth-user -P 2023-200_most_used_passwords.txt 127.0.0.1 http-get / -s 81
```

- `-l basic-auth-user`: This specifies that the username for the login attempt is 'basic-auth-user'.
- `-P 2023-200_most_used_passwords.txt`: This indicates that Hydra should use the password list contained in the file '2023-200_most_used_passwords.txt' for its brute-force attack.
- `127.0.0.1`: This is the target IP address, in this case, the local machine (localhost).
- `http-get /`: This tells Hydra that the target service is an HTTP server and the attack should be performed using HTTP GET requests to the root path ('/').
- `-s 81`: This overrides the default port for the HTTP service and sets it to 81.

## <mark class="hltr-cyan">Login Forms</mark>


After analyzing the login form's structure and behavior, it's time to build the `params` string, a critical component of Hydra's <mark class="hltr-green">http-post-form</mark> attack module. This string encapsulates the data that will be sent to the server with each login attempt, mimicking a legitimate form submission.

The `params` string consists of key-value pairs, similar to how data is encoded in a POST request. Each pair represents a field in the login form, with its corresponding value.

- `Form Parameters`: These are the essential fields that hold the username and password. Hydra will dynamically replace placeholders (`^USER^` and `^PASS^`) within these parameters with values from your wordlists.
- `Additional Fields`: If the form includes other hidden fields or tokens (e.g., CSRF tokens), they must also be included in the `params` string. These can have static values or dynamic placeholders if their values change with each request.
- `Success Condition`: This defines the criteria Hydra will use to identify a successful login. It can be an HTTP status code (like `S=302` for a redirect) or the presence or absence of specific text in the server's response (e.g., `F=Invalid credentials` or `S=Welcome`).

Let's apply this to our scenario. We've discovered:

- The form submits data to the root path (`/`).
- The username field is named `username`.
- The password field is named `password`.
- An error message "Invalid credentials" is displayed upon failed login.

Therefore, our `params` string would be:

```
/:username=^USER^&password=^PASS^:F=Invalid credentials
```

```shell-session
hydra -L top-usernames-shortlist.txt -P 2023-200_most_used_passwords.txt -s 5000 http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials"
```

---

# <mark class="hltr-pink">Custom Wordlists</mark>

## <mark class="hltr-cyan">Username Anarchy</mark>

Even when dealing with a seemingly simple name like "Jane Smith," manual username generation can quickly become a convoluted endeavor. While the obvious combinations like `jane`, `smith`, `janesmith`, `j.smith`, or `jane.s` may seem adequate, they barely scratch the surface of the potential username landscape.

This is where `Username Anarchy` shines. It accounts for initials, common substitutions, and more, casting a wider net in your quest to uncover the target's username:

```shell-session
./username-anarchy Jane Smith > jane_smith_usernames.txt
```

## <mark class="hltr-cyan">CUPP</mark>

With the username aspect addressed, the next formidable hurdle in a brute-force attack is the password. This is where `CUPP` (Common User Passwords Profiler) steps in, a tool designed to create highly personalized password wordlists that leverage the gathered intelligence about your target.

Let's continue our exploration with Jane Smith. We've already employed `Username Anarchy` to generate a list of potential usernames. Now, let's use CUPP to complement this with a targeted password list.

The efficacy of CUPP hinges on the quality and depth of the information you feed it. It's akin to a detective piecing together a suspect's profile - the more clues you have, the clearer the picture becomes. So, where can one gather this valuable intelligence for a target like Jane Smith?

- `Social Media`: A goldmine of personal details: birthdays, pet names, favorite quotes, travel destinations, significant others, and more. Platforms like Facebook, Twitter, Instagram, and LinkedIn can reveal much information.
- `Company Websites`: Jane's current or past employers' websites might list her name, position, and even her professional bio, offering insights into her work life.
- `Public Records`: Depending on jurisdiction and privacy laws, public records might divulge details about Jane's address, family members, property ownership, or even past legal entanglements.
- `News Articles and Blogs`: Has Jane been featured in any news articles or blog posts? These could shed light on her interests, achievements, or affiliations.

CUPP will then take your inputs and create a comprehensive list of potential passwords:

- Original and Capitalized: `jane`, `Jane`
- Reversed Strings: `enaj`, `enaJ`
- Birthdate Variations: `jane1994`, `smith2708`
- Concatenations: `janesmith`, `smithjane`
- Appending Special Characters: `jane!`, `smith@`
- Appending Numbers: `jane123`, `smith2024`
- Leetspeak Substitutions: `j4n3`, `5m1th`
- Combined Mutations: `Jane1994!`, `smith2708@`

```shell-session
cupp -i
```

