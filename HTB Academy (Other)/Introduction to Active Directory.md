# <mark class="hltr-pink">Active Directory Structure</mark>

Active Directory is a directory service for Windows network environments. It is a distributed, hierarchical structure that allows for centralized management of an organization's resources, including users, computers, groups, network devices and file shares, group policies, servers and workstations, and trusts.

<mark class="hltr-green">Active Directory provides authentication and authorization within a Windows domain environment</mark>

At a very (simplistic) high level, an AD structure may look as follows:

```
INLANEFREIGHT.LOCAL/
├── ADMIN.INLANEFREIGHT.LOCAL
│   ├── GPOs
│   └── OU
│       └── EMPLOYEES
│           ├── COMPUTERS
│           │   └── FILE01
│           ├── GROUPS
│           │   └── HQ Staff
│           └── USERS
│               └── barbara.jones
├── CORP.INLANEFREIGHT.LOCAL
└── DEV.INLANEFREIGHT.LOCAL
```

![[Pasted image 20240818193654.png]]

The graphic below shows two forests, `INLANEFREIGHT.LOCAL` and `FREIGHTLOGISTICS.LOCAL`. The two-way arrow represents a bidirectional trust between the two forests, meaning that users in `INLANEFREIGHT.LOCAL` can access resources in `FREIGHTLOGISTICS.LOCAL` and vice versa. We can also see multiple child domains under each root domain. In this example, we can see that the root domain trusts each of the child domains, but the child domains in forest A do not necessarily have trusts established with the child domains in forest B. This means that a user that is part of `admin.dev.freightlogistics.local` would NOT be able to authenticate to machines in the `wh.corp.inlanefreight.local` domain by default even though a bidirectional trust exists between the top-level `inlanefreight.local` and `freightlogistics.local` domains. To allow direct communication from `admin.dev.freightlogistics.local` and `wh.corp.inlanefreight.local`, another trust would need to be set up.

![[Pasted image 20240818193055.png]]

---

# <mark class="hltr-pink">Active Directory Terminology</mark>

- **<mark class="hltr-red">Object</mark>**: An object can be defined as ANY resource present within an Active Directory environment such as OUs, printers, users, domain controllers, etc.

- **<mark class="hltr-red">Attributes</mark>**: Every object in Active Directory has an associated set of [attributes](https://docs.microsoft.com/en-us/windows/win32/adschema/attributes-all) used to define characteristics of the given object.

- <mark class="hltr-red">Schema</mark>: The Active Directory [schema](https://docs.microsoft.com/en-us/windows/win32/ad/schema) is essentially the blueprint of any enterprise environment. It defines what types of objects can exist in the AD database and their associated attributes. It holds information about each object. For example, users in AD belong to the class "user," and computer objects to "computer," and so on. Each object has its own information that are stored in Attributes. When an object is created from a class, this is called instantiation, and an object created from a specific class is called an instance of that class.

- **<mark class="hltr-red">Domain</mark>**: A domain is a logical group of objects such as computers, users, OUs, groups, etc. We can think of each domain as a different city within a state or country. Domains can operate entirely independently of one another or be connected via trust relationships.

- <mark class="hltr-red">Forest</mark>: A forest is a collection of Active Directory domains. It is the topmost container and contains all of the AD objects introduced below, including but not limited to domains, users, groups, computers, and Group Policy objects. A forest can contain one or multiple domains and be thought of as a state in the US or a country within the EU. Each forest operates independently but may have various trust relationships with other forests.

- <mark class="hltr-red">Tree</mark>: A tree is a collection of Active Directory domains that begins at a single root domain. A forest is a collection of AD trees. Each domain in a tree shares a boundary with the other domains. A parent-child trust relationship is formed when a domain is added under another domain in a tree. Two trees in the same forest cannot share a name (namespace). Let's say we have two trees in an AD forest: `inlanefreight.local` and `ilfreight.local`. A child domain of the first would be `corp.inlanefreight.local` while a child domain of the second could be `corp.ilfreight.local`. All domains in a tree share a standard Global Catalog which contains all information about objects that belong to the tree.

- <mark class="hltr-red">Container</mark>: Container objects hold other objects.

- <mark class="hltr-red">Leaf</mark>: Leaf objects do not contain other objects and are found at the end of the subtree hierarchy.

- <mark class="hltr-red">Global Unique Identifier (GUID)</mark>: A [GUID](https://docs.microsoft.com/en-us/windows/win32/adschema/a-objectguid) is a unique 128-bit value assigned when a domain user or group is created. This GUID value is unique across the enterprise. Every single object created by Active Directory is assigned a GUID. The GUID is stored in the `ObjectGUID` attribute. When querying for an AD object, we can query for its `objectGUID` value using PowerShell or search for it by specifying its distinguished name, GUID, SID, or SAM account name. GUIDs are used by AD to identify objects internally. Searching in Active Directory by GUID value is probably the most accurate and reliable way to find the exact object you are looking for. The `ObjectGUID` property `never` changes and is associated with the object for as long as that object exists in the domain.

- <mark class="hltr-green">Security principals</mark>: In AD, security principals are domain objects that can manage access to other resources within the domain.

- <mark class="hltr-red">Security Identifier (SID)</mark>: A [security identifier](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-principals), or SID is used as a unique identifier for a security principal or security group. Every account, group, or process has its own unique SID, which, in an AD environment, is issued by the domain controller and stored in a secure database. A SID can only be used once. Even if the security principle is deleted, it can never be used again in that environment to identify another user or group. When a user logs in, the system creates an access token for them which contains the user's SID, the rights they have been granted, and the SIDs for any groups that the user is a member of. This token is used to check rights whenever the user performs an action on the computer. There are also [well-known SIDs](https://ldapwiki.com/wiki/Wiki.jsp?page=Well-known%20Security%20Identifiers) that are used to identify generic users and groups. These are the same across all operating systems.

- <mark class="hltr-red">Distinguished Name (DN)</mark>: A [Distinguished Name (DN)](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ldap/distinguished-names) describes the full path to an object in AD (such as `cn=bjones, ou=IT, ou=Employees, dc=inlanefreight, dc=local`). In this example, the user `bjones` works in the IT department of the company Inlanefreight, and his account is created in an Organizational Unit (OU) that holds accounts for company employees. The Common Name (CN) `bjones` is just one way the user object could be searched for or accessed within the domain.

- <mark class="hltr-red">Relative Distinguished Name (RDN)</mark>: A [Relative Distinguished Name (RDN)](https://docs.microsoft.com/en-us/windows/win32/ad/object-names-and-identities) is a single component of the Distinguished Name that identifies the object as unique from other objects at the current level in the naming hierarchy. In our example, `bjones` is the Relative Distinguished Name of the object. AD does not allow two objects with the same name under the same parent container, but there can be two objects with the same RDNs that are still unique in the domain because they have different DNs. For example, the object `cn=bjones,dc=dev,dc=inlanefreight,dc=local` would be recognized as different from `cn=bjones,dc=inlanefreight,dc=local`.
	![[Pasted image 20240818203334.png]]


- <mark class="hltr-green">sAMAccountName</mark>: The [sAMAccountName](https://docs.microsoft.com/en-us/windows/win32/ad/naming-properties#samaccountname) is the user's logon name. Here it would just be `bjones`. It must be a unique value and 20 or fewer characters.

- <mark class="hltr-green">userPrincipalName</mark>: The [userPrincipalName](https://social.technet.microsoft.com/wiki/contents/articles/52250.active-directory-user-principal-name.aspx) attribute is another way to identify users in AD. This attribute consists of a prefix (the user account name) and a suffix (the domain name) in the format of `bjones@inlanefreight.local`. This attribute is not mandatory.

- <mark class="hltr-green">Global Catalog (GC)</mark>: A [global catalog (GC)](https://docs.microsoft.com/en-us/windows/win32/ad/global-catalog) is a domain controller that stores copies of ALL objects in an Active Directory forest. The GC stores a full copy of all objects in the current domain and a partial copy of objects that belong to other domains in the forest. Standard domain controllers hold a complete replica of objects belonging to its domain but not those of different domains in the forest. The GC allows both users and applications to find information about any objects in ANY domain in the forest. GC is a feature that is enabled on a domain controller and performs the following functions:

	- Authentication (provided authorization for all groups that a user account belongs to, which is included when an access token is generated)
	- Object search (making the directory structure within a forest transparent, allowing a search to be carried out across all domains in a forest by providing just one attribute about an object.)

- <mark class="hltr-green">Replication</mark>: [Replication](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/replication/active-directory-replication-concepts) happens in AD when AD objects are updated and transferred from one Domain Controller to another. Whenever a DC is added, connection objects are created to manage replication between them. These connections are made by the Knowledge Consistency Checker (KCC) service, which is present on all DCs. Replication ensures that changes are synchronized with all other DCs in a forest, helping to create a backup in case one domain controller fails.

- <mark class="hltr-green">Service Principal Name</mark>: A [Service Principal Name (SPN)](https://docs.microsoft.com/en-us/windows/win32/ad/service-principal-names) uniquely identifies a service instance. They are used by Kerberos authentication to associate an instance of a service with a logon account, allowing a client application to request the service to authenticate an account without needing to know the account name.

- <mark class="hltr-green">Group Policy Objects</mark>: [Group Policy Objects (GPOs)](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/policy/group-policy-objects) are virtual collections of policy settings. Each GPO has a unique GUID. A GPO can contain local file system settings or Active Directory settings. GPO settings can be applied to both user and computer objects. They can be applied to all users and computers within the domain or defined more granularly at the OU level.

- <mark class="hltr-green">Access Control List (ACL)</mark>: An [Access Control List (ACL)](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-control-lists) is the ordered collection of Access Control Entries (ACEs) that apply to an object.

- <mark class="hltr-green">Access Control Entries (ACE)</mark>: Each [Access Control Entry (ACE)](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-control-entries) in an ACL identifies a trustee (user account, group account, or logon session) and lists the access rights that are allowed, denied, or audited for the given trustee.

- <mark class="hltr-green">Discretionary Access Control List</mark>: DACLs define which security principles are granted or denied access to an object; it contains a list of ACEs. When a process tries to access a securable object, the system checks the ACEs in the object's DACL to determine whether or not to grant access. If an object does NOT have a DACL, then the system will grant full access to everyone, but if the DACL has no ACE entries, the system will deny all access attempts. ACEs in the DACL are checked in sequence until a match is found that allows the requested rights or until access is denied.

- <mark class="hltr-green">System Access Control List</mark>: Allows for administrators to log access attempts that are made to secured objects. ACEs specify the types of access attempts that cause the system to generate a record in the security event log.

- <mark class="hltr-green">Fully Qualified Domain Name</mark>: hostname.domain name.tld

- <mark class="hltr-red">Tombstone</mark>: A [tombstone](https://ldapwiki.com/wiki/Tombstone) is a container object in AD that holds deleted AD objects. When an object is deleted from AD, the object remains for a set period of time known as the `Tombstone Lifetime,` and the `isDeleted` attribute is set to `TRUE`. Once an object exceeds the `Tombstone Lifetime`, it will be entirely removed. Microsoft recommends a tombstone lifetime of 180 days to increase the usefulness of backups, but this value may differ across environments. Depending on the DC operating system version, this value will default to 60 or 180 days. If an object is deleted in a domain that does not have an AD Recycle Bin, it will become a tombstone object. When this happens, the object is stripped of most of its attributes and placed in the `Deleted Objects` container for the duration of the `tombstoneLifetime`. It can be recovered, but any attributes that were lost can no longer be recovered.

- <mark class="hltr-red">AD RECYCLE BIN</mark>: The [AD Recycle Bin](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/the-ad-recycle-bin-understanding-implementing-best-practices-and/ba-p/396944) was first introduced in Windows Server 2008 R2 to facilitate the recovery of deleted AD objects. When the AD Recycle Bin is enabled, any deleted objects are preserved for a period of time, facilitating restoration if needed. The biggest advantage of using the AD Recycle Bin is that most of a deleted object's attributes are preserved, which makes it far easier to fully restore a deleted object to its previous state.

- <mark class="hltr-red">SYSVOL</mark>: The [SYSVOL](https://social.technet.microsoft.com/wiki/contents/articles/8548.active-directory-sysvol-and-netlogon.aspx) folder, or share, stores copies of public files in the domain such as system policies, Group Policy settings, logon/logoff scripts, and often contains other types of scripts that are executed to perform various tasks in the AD environment. The contents of the SYSVOL folder are replicated to all DCs within the environment using File Replication Services (FRS). You can read more about the SYSVOL structure [here](https://networkencyclopedia.com/sysvol-share/#Components-and-Structure).

- <mark class="hltr-red">NTDS.DIT</mark>: The NTDS.DIT file can be considered the heart of Active Directory. It is stored on a Domain Controller at `C:\Windows\NTDS\` and is a database that stores AD data such as information about user and group objects, group membership, and, most important to attackers and penetration testers, the password hashes for all users in the domain. Once full domain compromise is reached, an attacker can retrieve this file, extract the hashes, and either use them to perform a pass-the-hash attack or crack them offline using a tool such as Hashcat to access additional resources in the domain. If the setting [Store password with reversible encryption](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) is enabled, then the NTDS.DIT will also store the cleartext passwords for all users created or who changed their password after this policy was set. While rare, some organizations may enable this setting if they use applications or protocols that need to use a user's existing password (and not Kerberos) for authentication.

---

# <mark class="hltr-pink">Active Directory Objects</mark>

What is an object? An object can be defined as ANY resource present within an Active Directory environment such as OUs, printers, users, domain controllers.

![[Pasted image 20240819010435.png]]

## <mark class="hltr-cyan">Users</mark>

Users are considered leaf objects, which means that they cannot contain any other objects within them.

A user object is considered a security principal and has a security identifier (SID) and a global unique identifier (GUID).

## <mark class="hltr-cyan">Contacts</mark>

A contact object is usually used to represent an external user and contains informational attributes such as first name, last name, email address, etc.

They are leaf objects and are NOT security principals (securable objects), so they don't have a SID, only a GUID. An example would be a contact card for a third-party vendor or a customer.

## <mark class="hltr-cyan">Printers</mark>

A printer object points to a printer accessible within the AD network. Like a contact, a printer is a `leaf object` and not a security principal, so it only has a GUID. Printers have attributes such as the printer's name, driver information, port number, etc.

## <mark class="hltr-cyan">Computers</mark>

A computer object is any computer joined to the AD network (workstation or server). Computers are `leaf objects` because they do not contain other objects.

However, they are considered security principals and have a SID and a GUID. Like users, they are prime targets for attackers since full administrative access to a computer (as the all-powerful `NT AUTHORITY\SYSTEM` account) grants similar rights to a standard domain user and can be used to perform the majority of the enumeration tasks that a user account can (save for a few exceptions across domain trusts.)

## <mark class="hltr-cyan">Shared Folders</mark>

A shared folder object points to a shared folder on the specific computer where the folder resides. 

Shared folders can be either accessible to everyone (even those without a valid AD account), open to only authenticated users, or be locked down to only allow certain users/groups access. Shared folders are NOT security principals and only have a GUID. A shared folder's attributes can include the name, location on the system, security access rights.

## <mark class="hltr-cyan">Groups</mark>

A group is considered a container object because it can contain other objects, including users, computers, and even other groups.

A group IS regarded as a security principal and has a SID and a GUID.

In AD, groups are a way to manage user permissions and access to other securable objects (both users and computers). Let's say we want to give 20 help desk users access to the Remote Management Users group on a jump host. Instead of adding the users one by one, we could add the group, and the users would inherit the intended permissions via their membership in the group.

In Active Directory, we commonly see what are called "[nested groups](https://docs.microsoft.com/en-us/windows/win32/ad/nesting-a-group-in-another-group)" (a group added as a member of another group), which can lead to a user(s) obtaining unintended rights. Nested group membership is something we see and often leverage during penetration tests.

Groups in AD can have many [attributes](http://www.selfadsi.org/group-attributes.htm), the most common being the name, description, membership, other groups that the group belongs to, etc.

## <mark class="hltr-cyan">Organizational Units (OUs)</mark>

An organizational unit, or OU, is a container that systems administrators can use to store similar objects for ease of administration.

OUs are often used for administrative delegation of tasks without granting a user account full administrative rights. For example, we may have a top-level OU called Employees and then child OUs under it for the various departments. If an account were given the right to reset passwords over the top-level OU, this user would have the right to reset passwords for all users in the company. However, if the OU structure were such that specific departments were child OUs of the Help Desk OU, then any user placed in the Help Desk OU would have this right delegated to them if granted.

Other tasks that may be delegated at the OU level include creating/deleting users, modifying group membership, managing Group Policy links, and performing password resets. OUs are very useful for managing Group Policy settings across a subset of users and groups within a domain. For example, we may want to set a specific password policy for privileged service accounts so these accounts could be placed in a particular OU and then have a Group Policy object assigned to it, which would enforce this password policy on all accounts placed inside of it. A few OU attributes include its name, members, security settings, and more.

## <mark class="hltr-cyan">Domain</mark>

A domain is the structure of an AD network.

Domains contain objects such as users and computers, which are organized into container objects: groups and OUs.

Every domain has its own separate database and sets of policies that can be applied to any and all objects within the domain. Some policies are set by default (and can be tweaked), such as the domain password policy. In contrast, others are created and applied based on the organization's need, such as blocking access to cmd.exe for all non-administrative users or mapping shared drives at log in.

## <mark class="hltr-cyan">Domain Controllers</mark>

Domain Controllers are essentially the brains of an AD network.

They handle authentication requests, verify users on the network, and control who can access the various resources in the domain. All access requests are validated via the domain controller and privileged access requests are based on predetermined roles assigned to users.
It also enforces security policies and stores information about every other object in the domain.

---

# <mark class="hltr-pink">Active Directory Functionality</mark>

## <mark class="hltr-cyan">FSMO Roles</mark>

There are five Flexible Single Master Operation (FSMO) roles. These roles can be defined as follows:
![[Pasted image 20240819142006.png]]

## <mark class="hltr-cyan">Trusts</mark>

A trust is used to establish `forest-forest` or `domain-domain` authentication, allowing users to access resources in (or administer) another domain outside of the domain their account resides in. A trust creates a link between the authentication systems of two domains.

![[Pasted image 20240819142840.png]]

![[Pasted image 20240819142949.png]]Trusts can be transitive or non-transitive.

- A transitive trust means that trust is extended to objects that the child domain trusts.

- In a non-transitive trust, only the child domain itself is trusted.


Trusts can be set up to be one-way or two-way (bidirectional).

- In bidirectional trusts, users from both trusting domains can access resources.
- In a one-way trust, only users in a trusted domain can access resources in a trusting domain, not vice-versa. The direction of trust is opposite to the direction of access.

---

# <mark class="hltr-pink">Active Directory Protocols</mark>

## <mark class="hltr-cyan">Kerberos</mark>

Kerberos has been the default authentication protocol for domain accounts since Windows 2000.

When a user logs into their PC, Kerberos is used to authenticate them via mutual authentication. Kerberos is a stateless authentication protocol based on tickets instead of transmitting user passwords over the network.

As part of Active Directory Domain Services (AD DS), Domain Controllers have a Kerberos Key Distribution Center (KDC) that issues tickets

### <mark class="hltr-orange">Kerberos Authentication Process</mark>

![[images/Pasted image 20240819165815.png]]

The Kerberos protocol uses port 88 (both TCP and UDP). When enumerating an Active Directory environment, we can often locate Domain Controllers by performing port scans looking for open port 88 using a tool such as Nmap.

## <mark class="hltr-cyan">DNS</mark>

Active Directory Domain Services (AD DS) uses DNS to allow clients (workstations, servers, and other systems that communicate with the domain) to locate Domain Controllers and for Domain Controllers that host the directory service to communicate amongst themselves.

## <mark class="hltr-cyan">LDAP</mark>

Active Directory supports [Lightweight Directory Access Protocol (LDAP)](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol) for directory lookups.

LDAP uses port 389, and LDAP over SSL (LDAPS) communicates over port 636.

AD stores user account information and security information such as passwords and facilitates sharing this information with other devices on the network. LDAP is the language that applications use to communicate with other servers that provide directory services. In other words, LDAP is how systems in the network environment can "speak" to AD.

![[Pasted image 20240819171256.png]]

❗: The relationship between AD and LDAP can be compared to Apache and HTTP. The same way Apache is a web server that uses the HTTP protocol, Active Directory is a directory server that uses the LDAP protocol.

## <mark class="hltr-cyan">NTLM Authentication</mark>

Aside from Kerberos and LDAP, Active Directory uses several other authentication methods which can be used (and abused) by applications and services in AD.

![[Pasted image 20240819180050.png]]

### <mark class="hltr-orange">LM</mark>

`LAN Manager` (LM or LANMAN) hashes are the oldest password storage mechanism used by the Windows operating system.

If in use, they are stored in the SAM database on a Windows host and the NTDS.DIT database on a Domain Controller.

❗: Due to significant security weaknesses in the hashing algorithm used for LM hashes, it has been turned off by default since Windows Vista/Server 2008. However, it is still common to encounter, especially in large environments where older systems are still used

### <mark class="hltr-orange">NTHash (NTLM)</mark>

![[Pasted image 20240819180820.png]]

An NTLM hash looks like this:
```shell-session
Rachel:500:aad3c435b514a4eeaad3b935b51304fe:e46b9e548fa0d122de7f59fb6d48eaa2:::
```

- `Rachel` is the username
- `500` is the Relative Identifier (RID). 500 is the known RID for the `administrator` account
- `aad3c435b514a4eeaad3b935b51304fe` is the LM hash and, if LM hashes are disabled on the system, can not be used for anything
- `e46b9e548fa0d122de7f59fb6d48eaa2` is the NT hash. This hash can either be cracked offline to reveal the cleartext value (depending on the length/strength of the password) or used for a pass-the-hash attack.

### <mark class="hltr-orange">NTLMv1</mark>

The NTLM protocol performs a challenge/response between a server and client using the NT hash. NTLMv1 uses both the NT and the LM hash, which can make it easier to "crack" offline after capturing a hash.

NTLMv1 Hash Example:
```shell-session
u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c
```

### <mark class="hltr-orange">NTLMv2</mark>

The NTLMv2 protocol was first introduced in Windows NT 4.0 SP4 and was created as a stronger alternative to NTLMv1.

NTLMv2 Hash Example:
```shell-session
admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030
```

---

# <mark class="hltr-pink">Users and Groups</mark>

## <mark class="hltr-cyan">Users</mark>

### <mark class="hltr-orange">Local Accounts</mark>

Local accounts are stored locally on a particular server or workstation.

Any rights assigned can only be granted to that specific host and will not work across the domain.

Local user accounts are considered security principals but can only manage access to and secure resources on a standalone host.

**default local user accounts**:
- <mark class="hltr-green">Administrator</mark>: this account has the SID `S-1-5-domain-500` and is the first account created with a new Windows installation. It has full control over almost every resource on the system. It cannot be deleted or locked, but it can be disabled or renamed.

- <mark class="hltr-green">Guest</mark>: this account is disabled by default. The purpose of this account is to allow users without an account on the computer to log in temporarily with limited access rights. By default, it has a blank password and is generally recommended to be left disabled because of the security risk of allowing anonymous access to a host.

- <mark class="hltr-green">SYSTEM</mark>: The SYSTEM (or `NT AUTHORITY\SYSTEM`) account on a Windows host is the default account installed and used by the operating system to perform many of its internal functions. SYSTEM is a service account and does not run entirely in the same context as a regular user. One thing to note with this account is that a profile for it does not exist, but it will have permissions over almost everything on the host. It does not appear in User Manager and cannot be added to any groups. A `SYSTEM` account is the highest permission level one can achieve on a Windows host and, by default, is granted Full Control permissions to all files on a Windows system.

- <mark class="hltr-green">Network Service</mark>: This is a predefined local account used by the Service Control Manager (SCM) for running Windows services.

- <mark class="hltr-green">Local Service</mark>: This is another predefined local account used by the Service Control Manager (SCM) for running Windows services. It is configured with minimal privileges on the computer and presents anonymous credentials to the network.

### <mark class="hltr-orange">Domain Users</mark>

Domain users differ from local users in that they are granted rights from the domain to access resources such as file servers, printers, intranet hosts, and other objects based on the permissions granted to their user account or the group that account is a member of.

One account to keep in mind is the `KRBTGT` account, however. This is a type of local account built into the AD infrastructure. This account acts as a service account for the Key Distribution service providing authentication and access for domain resources. This account is a common target of many attackers since gaining control or access will enable an attacker to have unconstrained access to the domain.

## <mark class="hltr-cyan">Groups</mark>

Groups are used to place users, computers, and contact objects into management units that provide ease of administration over permissions and facilitate the assignment of resources such as printers and file share access.

Groups in Active Directory have two fundamental characteristics: `type` and `scope`. The `group type` defines the group's purpose, while the `group scope` shows how the group can be used within the domain or forest.

![[Pasted image 20240820153918.png]]

### <mark class="hltr-orange">Group Types</mark>

There are two main types: `security` and `distribution` groups.

- The `Security groups` type is primarily for ease of assigning permissions and rights to a collection of users instead of one at a time. They simplify management and reduce overhead when assigning permissions and rights for a given resource. All users added to a security group will inherit any permissions assigned to the group, making it easier to move users in and out of groups while leaving the group's permissions unchanged.

- The `Distribution groups` type is used by email applications such as Microsoft Exchange to distribute messages to group members. They function much like mailing lists. This type of group cannot be used to assign permissions to resources in a domain environment.

### <mark class="hltr-orange">Group Scopes</mark>

There are three different `group scopes` that can be assigned when creating a new group.

1. Domain Local Group
2. Global Group
3. Universal Group

#### <mark class="hltr-grey">Domain Local Group</mark>

Domain local groups can only be used to manage permissions to domain resources in the domain where it was created. Local groups cannot be used in other domains but `CAN` contain users from `OTHER` domains. Local groups can be nested into (contained within) other local groups but `NOT` within global groups.

#### <mark class="hltr-grey">Global Group</mark>

Global groups can be used to grant access to resources in `another domain`. A global group can only contain accounts from the domain where it was created. Global groups can be added to both other global groups and local groups.

#### <mark class="hltr-grey">Universal Group</mark>
The universal group scope can be used to manage resources distributed across multiple domains and can be given permissions to any object within the same `forest`. They are available to all domains within an organization and can contain users from any domain.

#### <mark class="hltr-grey">AD Group Scope Example</mark>

```powershell-session
Get-ADGroup  -Filter * |select samaccountname,groupscope

samaccountname                           groupscope
--------------                           ----------
Administrators                          DomainLocal
Users                                   DomainLocal
Guests                                  DomainLocal
Print Operators                         DomainLocal
Backup Operators                        DomainLocal
Replicator                              DomainLocal
Remote Desktop Users                    DomainLocal
Network Configuration Operators         DomainLocal
Distributed COM Users                   DomainLocal
IIS_IUSRS                               DomainLocal
Cryptographic Operators                 DomainLocal
Event Log Readers                       DomainLocal
Certificate Service DCOM Access         DomainLocal
RDS Remote Access Servers               DomainLocal
RDS Endpoint Servers                    DomainLocal
RDS Management Servers                  DomainLocal
Hyper-V Administrators                  DomainLocal
Access Control Assistance Operators     DomainLocal
Remote Management Users                 DomainLocal
Storage Replica Administrators          DomainLocal
Domain Computers                             Global
Domain Controllers                           Global
Schema Admins                             Universal
Enterprise Admins                         Universal
Cert Publishers                         DomainLocal
Domain Admins                                Global
Domain Users                                 Global
```
