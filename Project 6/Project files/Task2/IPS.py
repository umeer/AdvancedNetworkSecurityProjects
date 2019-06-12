#!/usr/bin/env python
from netfilterqueue import NetfilterQueue
import threading, time

from scapy.config import conf
from scapy.supersocket import L3RawSocket
from scapy.all import *


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


SERVER_IP = "192.168.1.113"
THRESHOLD = 2

ipList = []
packetList = []
reqCounter = []

outGoingPacket = []

kruger = ""


lock = threading.Lock()


def sendRST(stringIp,sportI):
	conf.L3socket=L3RawSocket
	ip = IP(src=stringIp,dst=SERVER_IP)
	syn = TCP(sport=sportI, dport=80, flags='R', seq=1000)
	packet = ip/syn
	send(packet,iface="lo")
	print "packet rst sent"
	
	
	

def isAllGood(data, packet):		
	for i in range (len(ipList)):
		if data[IP].src == ipList[i]:
			reqCounter[i] = reqCounter[i] + 1
			print "This appered #"+ str(reqCounter[i])+" times"
			if reqCounter[i] > THRESHOLD:
				if reqCounter[i]-1==THRESHOLD:
					sendRST(data[IP].src, data[TCP].sport)
				#sendSYN(data[IP].src, data[TCP].sport, data[TCP].seq)#sendRST(string,sport)
				global packetList
				packetList.append(packet)
				return 0
			else:
				return 1
			
	ipList.append(data[IP].src)
	reqCounter.append(0)
	print "It is a new IP"
	return 1

def sendOutKruger(ipString):
	global packetList
	
	for j in range (len(packetList)):
		data = IP(packetList[j].get_payload())
		thisPacketIpAddress = data[IP].src
		if thisPacketIpAddress == ipString:
			packetList[j].accept()
			packetList.pop(j)
			return
			
			
 
	
def delayer(running): #this function send the packet after are being slow down
	while running.is_set():
		lock.acquire()
		try:
			for i in range (len(ipList)):		
				if reqCounter[i]>THRESHOLD:
					sendOutKruger(ipList[i])
					print "ip: "+ ipList[i] + " has been sent remain: "+ str(reqCounter[i]-1)
					#sendSYNPRO(ipList[i])
					#outGoingPacket.append(ipList[i])
				if reqCounter[i]>0:
					reqCounter[i]=reqCounter[i]-1
					print "cool down for ip: " + ipList[i] +" is now "+ str(reqCounter[i])
		finally:
			lock.release()
							
		time.sleep(1)
		
		
def removeIPFromList(data):
	global packetList
	
	print "start data removed for this packet"
	for j in range (len(packetList)):
		data2 = IP(packetList[j].get_payload())
		thisPacketIpAddress = data2[IP].src
		if data[IP].src == thisPacketIpAddress:
			packetList.pop(j)
			
	for k in range (len(ipList)):		
		if ipList[k] == data[IP].src:
			ipList.pop(k)
			reqCounter.pop(k)
	print "data removed for this packet"


	

def print_and_accept(packet):

	lock.acquire()
	try:
		data = IP(packet.get_payload())
				
		if data.tos == 0:
			print (data[IP].src)+" "+str(data[TCP].sport)
			typeTCP = data[TCP].flags
			#data.show()
			
			if typeTCP & SYN and typeTCP & ACK:
				print "this is a SYN ACK"
			else:
				if typeTCP & FIN and typeTCP & ACK:
					print "this is a FIN ACK"
				else:
					if typeTCP & SYN:
						print "this is a SYN"
						if isAllGood(data, packet) == 1:
							packet.accept()
							return
						else:
							print "this is fishy, let slow it down-> kruger mode"
							return
					else:
						if typeTCP & FIN:
							print "this is a FIN"
						else:
							if typeTCP & ACK:
								print "this is a ACK"
								#removeIPFromList(data)
							else:
								if typeTCP & RST:
									print "this is a RST"
						
		packet.accept()
	finally:
		lock.release()



	
running = threading.Event()
running.set()

thread = threading.Thread(target=delayer, args=(running,))
thread.start()

nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)



try:
	nfqueue.run()
except KeyboardInterrupt:
    print('')
	
running.clear()
thread.join()

nfqueue.unbind()