---
title: "Marco"
date: 2025-08-20
draft: false
summary: "Exploring Marco — a blend of simplicity and precision in the digital realm."
description: "Marco is more than just a name — it represents clarity, focus, and the art of navigating complex systems with elegance. This post dives into its meaning, applications, and lessons it brings."
tags: ["redteam", "phishing", "office365"]
layoutBackgroundBlur: true
---

## Basic

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

## Weaponized Macros

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

### Attack Rating
- **High Realism**: Macro-based attacks continue to appear in real-world incidents, targeting both IT and non-IT staff.  
- **Social Engineering Factor**: Success often relies on persuading the user to click *Enable Content*, a surprisingly common behavior in corporate environments.  
- **Critical Risk**: If macros are enabled by default (or policies are poorly enforced), the attack vector becomes a severe vulnerability.  
- **Bypassing Defenses**: With obfuscation, sandbox detection, and sheet-hiding techniques, many traditional antivirus solutions can be evaded. Advanced variants also bypass some EDR tools by injecting into trusted processes.  
- **Persistence & Payload Delivery**: Weaponized macros can be chained to download and execute secondary payloads (e.g., Meterpreter, Cobalt Strike), establishing long-term access.  
- **Detection Difficulty**: When combined with living-off-the-land techniques (e.g., abusing PowerShell or WMI), attribution and detection become harder for defenders.  


### References

[Phishing with MS Office](https://www.ired.team/offensive-security/initial-access/phishing-with-ms-office)

[EXCEL 4.0 XLM macro in MacroPack Pro](https://blog.sevagas.com/?EXCEL-4-0-XLM-macro-in-MacroPack-Pro)
