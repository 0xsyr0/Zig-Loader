#!/usr/bin/env python3
import sys
import os

def encrypt_shellcode(shellcode_bytes, xor_key):
    encrypted = bytearray()
    for i, byte in enumerate(shellcode_bytes):
        key_byte = xor_key[i % len(xor_key)]
        encrypted.append(byte ^ key_byte)
    return encrypted

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 encrypt.py <shellcode_file>")
        print("\nExample:")
        print("  python3 encrypt.py shellcode.bin")
        sys.exit(1)
    
    shellcode_file = sys.argv[1]
    
    if not os.path.exists(shellcode_file):
        print(f"Error: File '{shellcode_file}' not found")
        sys.exit(1)
    
    with open(shellcode_file, 'rb') as f:
        shellcode = f.read()
    
    if len(shellcode) == 0:
        print("Error: Shellcode file is empty")
        sys.exit(1)
    
    xor_key = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]
    
    encrypted = encrypt_shellcode(shellcode, xor_key)
    
    decrypted = encrypt_shellcode(encrypted, xor_key)
    if bytes(decrypted) == shellcode:
        print(f"[+] Encryption verification: PASSED")
    else:
        print(f"[-] Encryption verification: FAILED")
        sys.exit(1)
    
    print(f"[+] Original size: {len(shellcode)} bytes")
    print(f"[+] Encrypted size: {len(encrypted)} bytes")
    print()
    
    print("const encrypted_shellcode = [_]u8{")
    for i in range(0, len(encrypted), 14):
        chunk = encrypted[i:i+14]
        print("    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    print("};")
    print()
    print("const xor_key = [_]u8{", end="")
    print(", ".join(f"0x{b:02x}" for b in xor_key), end="")
    print("};")
    
    with open('data.bin', 'wb') as f:
        f.write(encrypted)
    
    print()
    print(f"[+] Encrypted data written to: data.bin")

if __name__ == "__main__":
    main()
