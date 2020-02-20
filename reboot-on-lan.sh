#!/bin/bash

target_mac=08:00:27:02:8a:60
target_ip="192.168.0.101" # IPv6 works too
password='darnit'
frame=$(echo -n $(printf 'f%.0s' {1..12}; printf "$(echo -n $target_mac | sed 's/://g')%.0s" {1..16}) | sed -e 's/../\\x&/g')
magic=$(echo -n "$frame""$password")

echo -ne "$magic" > /dev/udp/$target_ip/9
