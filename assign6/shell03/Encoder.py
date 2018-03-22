#!/usr/bin/python

# Encoder.py
# Author: jcarabantes
# Student Id: SLAE-1058

strings = []

strings.append("\x77\x6f\x64\x61")
strings.append("\x68\x73\x2f\x63")
strings.append("\x74\x65\x2f\x2f")

encoded = ""
original = ""

print('Encoding ...')

for c in strings:
	for x in bytearray(c) :
		y = ~x

		original += '%02x' % x
		encoded += '%02x' % (y & 0xff)

	print("Original: 0x{0} -> 0x{1}".format(original, encoded))
	
	# reset
	encoded = ""
	original = ""

