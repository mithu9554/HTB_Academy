#!/bin/bash
grep -E '^[A-Z]' /usr/share/wordlists/rockyou.txt | grep '[0-9]$' | grep '[^A-Za-z0-9]' | awk 'length >= 20 && length <= 29'