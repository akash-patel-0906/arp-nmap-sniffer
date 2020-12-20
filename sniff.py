from scapy.all import *
from collections import defaultdict
import csv
import os

dictionary={}

ip_dict={}

final_dict={}

final_ips=[]

with open("output.csv", "a") as fp:
    wr = csv.writer(fp, dialect='excel')
    wr.writerow(("IP", "MAC Address"))

def monitor(pkt):
    if ARP in pkt and pkt[ARP].op in (1,2):
        mac_address = pkt.sprintf("%ARP.hwsrc%")
        ip = pkt.sprintf("%ARP.psrc%")
        if not ip in dictionary:
            dictionary[ip] = mac_address
            #print(dictionary[ip])s
        if ip not in ip_dict:
             ip_dict[ip] = mac_address
        
count=0   
while count<4:
    sniff(prn=monitor,filter="arp", store=0, timeout=20)
    for ip in ip_dict:
        if not ip in final_dict:
            final_dict[ip]=ip_dict[ip]
            final_ips.append(ip)
            print(ip + " " + final_dict[ip])    
            with open("output.csv", "a") as fp:
                wr = csv.writer(fp, dialect='excel')
                wr.writerow((ip, final_dict[ip]))
            

    dictionary.clear()
    ip_dict.clear()
    count=count+1
    
print("###########")
print("###########")
print("###########")
print("###########")

print("Nmap scan starting")

for ip in final_ips:
    command = "nmap " + " -sS -D 10.7.1.80 -O " + ip #change to whatever you want

    #sudo nmap --script vuln ip
    process = os.popen(command)
    results = str(process.read())
    print(results)

    file=open("nmap_output.txt", "a")
    file.write(results + "\n")
    file.close()
    

        