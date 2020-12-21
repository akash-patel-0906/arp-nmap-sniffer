# arp-nmap-sniffer

*Description

This program messes around with a more covert ARP scan as well as a customizable Nmap scan. It waits for other devices on the local network to send ARP packets and then notes their IPs and MAC addresses into a CSV file.

After the ARP scan, the program then runs an nmap scan and saves the outputs to a .txt file.

Run <code> python3 sniff.py </code>.

*To customize the nmap scan, open sniff.py and change the command at line 53.*
