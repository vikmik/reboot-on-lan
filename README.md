# reboot-on-lan

A silly Linux kernel module that allows a machine to be rebooted remotely with a single network packet.\
Why? If you're often messing with a system over SSH, you'll probably understand why this can be useful. Indeed, even if the machine doesn't respond to SSH anymore, you may be able to reboot it and start fresh!

# Instructions
1. Build and insert the kernel module on the machine that will need to be rebooted. If you really love this module, you can autoload it on every boot.
2. On your local machine, edit `reboot-on-lan.sh` and update the IP and MAC address (and password, if you changed it)
3. Execute `reboot-on-lan.sh`. This sends a magic packet that triggers the reboot.

# Disclaimer
* Use at your own risk! And especially don't use it at work. This is a truly horrible solution. The magic packet will transit unencrypted.\
Anyone who learns your IP/MAC address/password (that includes anyone who can see your traffic) will be able to reboot your machine.
* This requires the machine to have a running kernel with working IP connectivity.
* The network packet will trigger an emergency restart - see https://github.com/torvalds/linux/blob/457c89965399115e5cd8bf38f9c597293405703d/kernel/reboot.c#L56\
This is the same thing that happens when you use the Magic SysRQ (Alt+PrintScreen+B).\
If you don't like this, you can change the module code to issue an `orderly_reboot()` instead.

# Notes
This reuses the same "Magic Packet" format as Wake-on-LAN ( https://en.wikipedia.org/wiki/Wake-on-LAN )\
As opposed to Wake-on-LAN, since this module requires the remote machine to have an IP address, there's no need for directed broadcast support or a static ARP table on the router. It should work out of the box as long as the machine is reachable via IP.
