---
title: "Remote SSH"
date: 2025-08-24
draft: false
summary: "Exploring malicious remote SSH access and its red team implications."
description: "Hands-on look at Remote SSH techniques, from initial access to potential misuse in phishing and red team scenarios."
tags: ["redteam", "ssh", "phishing", "vscode", "remote-access"]
layoutBackgroundBlur: true
showDate: true
showAuthor: false
---

## Scenarios


Update: [Mauro Soria](https://www.linkedin.com/in/mauro-soria-63268b22/) pointed out that this attack vector can be easily adapted for phishing scenarios:

1. Share a GitHub repo

2. Give some instructions to access the attacker server with Cursor or VS Code.


## POC

<video width="1000" height="800" controls align="center">
  <source src="poc/POC.mp4" type="video/mp4">
Your browser does not support the video tag.
</video>

[poc](https://github.com/OdanBroder/VSCode-RemoteBreakout/tree/main)

## References

[“Vibe Hacking”: Abusing Developer Trust in Cursor and VS Code Remote Development](https://blog.calif.io/p/vibe-hacking-abusing-developer-trust)

[VsCodeExtLure](https://github.com/securezeron/VsCodeExtLure)