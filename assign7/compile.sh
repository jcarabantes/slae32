#!/bin/bash

echo '[+] Doing backup to /tmp...'
cp $1.nasm /tmp

echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o $1.o $1.nasm

echo '[+] Linking ...'
ld -o $1 $1.o

echo '[+] Done!'



