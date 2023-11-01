import os,time
from scapy.all import *

def banner():
    print("""
 _______   __   ___  _____              _             
/  ___\ \ / / \ | | |_   _|            | |            
\ `--. \ V /|  \| |   | |_ __ __ _  ___| | _____ _ __ 
 `--. \ \ / | . ` |   | | '__/ _` |/ __| |/ / _ \ '__|
/\__/ / | | | |\  |   | | | | (_| | (__|   <  __/ |   
\____/  \_/ \_| \_/   \_/_|  \__,_|\___|_|\_\___|_| V1.0 Release
    
Tools Atau Alat Untuk Mendeteksi SYN Pocket Dari Pengguna Yang Mengakses Dan Bisa Juga
Digunakan Untuk Mendeteksi Serangan SYN Flood Attack
    """)

def packet_callback(packet):
    tgl = time.strftime("%m/%d/%Y", time.localtime())
    waktu = time.strftime("%H:%M:%S", time.localtime())

    if packet.haslayer(TCP) and packet[TCP].flags & 0x02:
        print(f"[ ! ] {tgl} {waktu} | Detected SYN packet from {packet[IP].src}")

def main():
    if os.name == "nt":
        system("cls")
    else:
        system("clear")
        
    banner()
    sniff(filter="tcp", prn=packet_callback)

if __name__ == '__main__':
    main()