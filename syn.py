import os,time
from scapy.all import*
def banner():print("\n _______   __   ___  _____              _             \n/  ___\\ \\ / / \\ | | |_   _|            | |            \n\\ `--. \\ V /|  \\| |   | |_ __ __ _  ___| | _____ _ __ \n `--. \\ \\ / | . ` |   | | '__/ _` |/ __| |/ / _ \\ '__|\n/\\__/ / | | | |\\  |   | | | | (_| | (__|   <  __/ |   \n\\____/  \\_/ \\_| \\_/   \\_/_|  \\__,_|\\___|_|\\_\\___|_| V1.0 Release\n    \nTools Atau Alat Untuk Mendeteksi SYN Pocket Dari Pengguna Yang Mengakses Dan Bisa Juga\nDigunakan Untuk Mendeteksi Serangan SYN Flood Attack\n    ")
def packet_callback(packet):
	tgl=time.strftime('%m/%d/%Y',time.localtime());waktu=time.strftime('%H:%M:%S',time.localtime())
	if packet.haslayer(TCP)and packet[TCP].flags&2:print(f"[ ! ] {tgl} {waktu} | Detected SYN packet from {packet[IP].src}")
def main():
	if os.name=='nt':os.system('cls')
	else:os.system('clear')
	banner();sniff(filter='tcp',prn=packet_callback)
if __name__=='__main__':main()
