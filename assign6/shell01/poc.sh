#!/bin/sh

echo "[x] Adding iptable rules\n"
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT 
sudo iptables -L

echo "\n\n[x] Executing shellcode\n"
sudo ./$1
echo "\n\n[x] Executing iptables -L\n"
sudo iptables -L
