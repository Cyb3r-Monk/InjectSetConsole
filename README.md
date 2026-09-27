# InjectSetConsole

**InjectSetConsole** performs process code injection by leveraging a **Windows named pipe**.

Unlike traditional techniques, **it does not use the VirtualAllocEx and WriteProcessMemory APIs**.

### Command Line Syntax

**InjectSetConsole.exe `<executable_path`>**

**executable_path**: netsh.exe, nslookup.exe,... or other nteractive console program

_Example: InjectSetConsole.exe C:\Windows\System32\netsh.exe_

To use different shellcode, replace the bytes starting at offset **0x19** (hexadecimal) in the **rawData** array.

Alternatively, you can modify the search pattern to improve evasion.

## Links

[EDR Evasion: Process Injection Without WriteProcessMemory](https://www.zerosalarium.com/2026/09/edr-evasion-process-injection-without-WriteProcessMemory.html)


## Demo Video

Youtube EDRChoker: [https://youtu.be/hj05mT-45bo](https://youtu.be/hj05mT-45bo)


## 🐦 Enjoying my work? Support the journey by following me on X

[![Twitter Follow](https://img.shields.io/twitter/follow/TwoSevenOneT?style=for-the-badge&logo=x&color=000)](https://x.com/TwoSevenOneT)

## Author:

[Two Seven One Three](https://x.com/TwoSevenOneT)
