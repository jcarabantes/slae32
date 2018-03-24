#!/usr/bin/env python

# wrapper.py
# Author: jcarabantes
# Student Id: SLAE-1058

import struct
import sys
import socket
import argparse
import os
import time

# output functions
def info(m, new_line=None):
	print("\033[1m\033[34m[INFO]\033[0m {0}".format(m))
	if new_line: print("")

def debug(m, new_line=None):
	global verbose
	if verbose: print("\033[1m\033[32m[DEBUG]\033[0m {0}".format(m))
	if verbose and new_line: print("")

def error(m):
	print("\033[1m\033[31m[ERROR]\033[0m {0}".format(m))
	sys.exit(1)

def check_ip_format(ip):
	try:
		i = socket.inet_aton(ip)
		return True
	except Exception as e:
		return False

def get_hex_port(h):
        bs = []
        for x in xrange(0, len(h), 2):
                bs.append("{0}".format(h[x:x+2]))
        return '' + ''.join(bs)

def compile_shellcode(original_name):

	cmd_copy = "cp {0}.nasm /tmp".format(original_name)
	debug('Doing backup: {0}'.format(cmd_copy))
	os.system(cmd_copy)

	cmd_nasm = "nasm -f elf32 -o {0}.o {0}.nasm".format(original_name)
	debug('Assembling with Nasm: {0}'.format(cmd_nasm))
	os.system(cmd_nasm)

	cmd_ld = "ld -o {0} {0}.o".format(original_name)
	debug('Linking: {0}'.format(cmd_ld))
	os.system(cmd_ld)

def clean(file_name):
	os.system("rm {0}.*".format(file_name))

def show_opcodes(file_name):
	os.system("for i in $(objdump -d {0} -M intel |grep \"^ \" |cut -f2); do echo -n '\\x'$i; done;echo".format(file_name))
	print("")

parser = argparse.ArgumentParser(description='Bind TCP Wrapper - Shellcode generator')
parser.add_argument('port', nargs=1, help="Port Number to connecto to")
parser.add_argument('template', nargs=1, help="Full path where shellcode template is located")
parser.add_argument('--output', '-o', help="Output name for the new shellcode. Default (scode_time.nasm)")
parser.add_argument('--verbose', '-v', action="store_true", help="Verbose")
parser.add_argument('--stdout', '-s', action="store_true", help="Show shellcode opcodes in STDOUT")

args,l = parser.parse_known_args()

verbose = args.verbose
stdout = args.stdout
port = args.port[0]
template = args.template[0]
output = "scode_{0}".format(time.strftime('%H%m%s')) if args.output is None else args.output

info("Staring process")

debug("Port number: {0}".format(port))
debug("Using template: {0}".format(template))
debug("Output file: {0}".format(output), True)

if int(port) <= 0 or int(port) > 65535:
	error("Invalid port number")


int_port = port
long_hex_port = struct.pack("<L",int(int_port)).encode('hex')[:4]

new_port = get_hex_port(long_hex_port)

debug("Long port hex: {0} (null bytes are checked too)".format(new_port))
debug("Opening template")

f = open(template, "r")
replaced = f.read()
port_1 = "0x" + new_port[:2] if new_port[:2] != "00" else "dl"
port_2 = "0x" + new_port[2:] if new_port[2:] != "00" else "dl"

new_asm_content = replaced.format(port_2, port_1)
f.close()

f2 = open("{0}.nasm".format(output), "w")
f2.write(new_asm_content)
f2.close()

debug("Tmp asm file has been written in {0}.nasm".format(output), True)
info("Compiling ...")

time.sleep(1)
compile_shellcode(output)
clean(output)
info("Process ended")
info("New binary created: ./{0}".format(output))

if stdout:
	info("Using objdump to dump opcodes", True)
	show_opcodes(output)
