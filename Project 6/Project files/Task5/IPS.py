#!/usr/bin/env python
from netfilterqueue import NetfilterQueue
import threading, time, datetime, os
from datetime import timedelta

from scapy.config import conf
from scapy.supersocket import L3RawSocket
from scapy.all import *
import scapy_http.http


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


INTERFACE_NAME  = "enp0s3"
SERVER_IP = "192.168.1.113"
SERVER_PORT = 80
HASH_SEED_SECRET = ""


ipTrust = []
seqNumerOfIpTrust = []

ipWhiteList = []


packetToIgnore = []



def make_random_password():
	return ''+str(os.urandom(16))

	

def isThisToIgnore (packetCode):
	for j in range (len(packetToIgnore)):
		if packetCode == packetToIgnore[j]:
			return 1
		else:
			return 0
		
		
def removePacketToIgnore(packetCode):
	for j in range (len(packetToIgnore)):
		if packetCode == packetToIgnore[j]:
			packetToIgnore.pop(j)
	


def sendRST(stringIp,sportI):
	conf.L3socket=L3RawSocket
	ip = IP(src=stringIp,dst=SERVER_IP)
	syn = TCP(sport=sportI, dport=SERVER_PORT, flags='R', seq=1000)
	packet = ip/syn
	send(packet,iface="lo")
	print "packet rst sent"
	
	
	
def sendSYNACK(packet): # To the client
	cookie = buildCookie(packet)
	seqe = packet[TCP].seq +1
	print "out - this is a SYN-ACK with seq:"+ str(cookie) + " ack:"+ str(seqe)
	s = conf.L3socket(iface=INTERFACE_NAME)
	ip = IP(src=SERVER_IP, dst=packet[IP].src)
	syn = TCP(sport=SERVER_PORT, dport=packet[TCP].sport, flags='SA', seq=cookie, ack= seqe)
	packet = ip/syn
	s.send(packet)
	
def sendSYN(packet): # To the server
	num = packet[TCP].seq-1 # it should be -2 but my client is not increasing the seq in the ack
	print "ignore this " + str(num)
	packetToIgnore.append(num)	
	conf.L3socket=L3RawSocket
	ip = IP(src=packet[IP].src, dst=SERVER_IP)
	syn = TCP(sport=packet[TCP].sport, dport=SERVER_PORT, flags='S', seq = num)
	packet = ip/syn
	send(packet,iface="lo")	
	print "internal syn sent"

	
def sendACK(packet): # To the server
	num = packet[TCP].ack+1
	print "ignore this " + str(num)
	packetToIgnore.append(num)	
	conf.L3socket=L3RawSocket
	ip = IP(src=packet[IP].src, dst=SERVER_IP)
	syn = TCP(sport=packet[TCP].sport, dport=SERVER_PORT, flags='A', seq=num, ack =packet[TCP].seq+1)
	packet = ip/syn
	send(packet,iface="lo")
	print "internal ack sent"


	
	
def buildCookie(packet):
	time = datetime.datetime.now().strftime("%y-%m-%d-%H-%M")
	ipCliet = packet[IP].src
	clientPort = packet[TCP].sport
	ipServer = packet[IP].dst
	serverPort = packet[TCP].dport	
	hashValue = abs(hash(time + ipCliet + str(clientPort) +ipServer + str(serverPort) + HASH_SEED_SECRET))% 4294967295
	
	# print "##the cookie is: " + str(hashValue)
	return hashValue

	
	
def testCookie(packet): #This functin checks it the client response is correct 
	time = datetime.datetime.now().strftime("%y-%m-%d-%H-%M")
	ipClient = packet[IP].src
	clientPort = packet[TCP].sport
	ipServer = packet[IP].dst
	serverPort = packet[TCP].dport	
	hashValueNow = abs(hash(time + ipClient + str(clientPort) +ipServer + str(serverPort) + HASH_SEED_SECRET))% 4294967295
	
	time = (datetime.datetime.now()+timedelta(0,-60)).strftime("%y-%m-%d-%H-%M")
	hashValuePast = abs(hash(time + ipClient + str(clientPort) +ipServer + str(serverPort) + HASH_SEED_SECRET))% 4294967295

	time = (datetime.datetime.now()+timedelta(0,60)).strftime("%y-%m-%d-%H-%M")
	hashValueFut = abs(hash(time + ipClient + str(clientPort) +ipServer + str(serverPort) + HASH_SEED_SECRET))% 4294967295

	# print "##the cookie reply is: " + str(hashValuePast) +" "+  str(hashValueNow) +" "+ str(hashValueFut)

	replySeqNumber = packet[TCP].ack-1
	
	if replySeqNumber == hashValuePast or replySeqNumber == hashValueNow or replySeqNumber == hashValueFut:
		return 1
	else:
		return 0

		
		

def setIpTrust(pacekt):
	ipTrust.append(pacekt[IP].src)
	seqNumerOfIpTrust.append(pacekt[TCP].seq-1) # it should be -2 but my client is not increasing the seq in the ack
	
		
def whiteListIp(seqNumber):
	for i in range (len(ipTrust)):
		if seqNumerOfIpTrust[i] == seqNumber:
			print "trustig the ip: "+ipTrust[i]
			ipWhiteList.append(ipTrust[i])
			ipTrust.pop(i)
			seqNumerOfIpTrust.pop(i)
			return

def checkWhiteList(ip):
	for i in range (len(ipWhiteList)):
		if ipWhiteList[i] == ip:
			return 1
		else:
			return 0
			

	


def print_and_accept(packet):
	data = IP(packet.get_payload())
	
	if data[TCP].dport == SERVER_PORT: #this is what is entering the server
	
		if data.haslayer("HTTP") and data["HTTP"].Method == "GET":  #let filter out all the interesting packet
			print "in - this is a HTTP GET requesting the path "+ data["HTTP"].Path
			if checkWhiteList(data[IP].src) == 1:
				packet.accept()
				return
			else:
				packet.drop()
				return
		else:
				
			if data.tos == 0:
				#print (data[IP].src)+" "+str(data[TCP].sport)
				typeTCP = data[TCP].flags
				
				if typeTCP & SYN and typeTCP & ACK:
					print "in - this is a SYN ACK" + " seq:" + str(data[TCP].seq) +" ack:"+ str(data[TCP].ack)
				else:
					if typeTCP & FIN and typeTCP & ACK:
						print "in - this is a FIN ACK"
					else:
						if typeTCP & SYN:
							print "in - this is a SYN" + " seq:"+ str(data[TCP].seq) +" ack:"+ str(data[TCP].ack)
							if checkWhiteList(data[IP].src) == 1:
								packet.accept()
								return
							else:
								if isThisToIgnore(data[TCP].seq) == 1: #this is a loopback to the server
									print "*this is a loopback packet"
									removePacketToIgnore(data[TCP].seq)
									packet.accept()
									return
								else:
									packet.drop()
									sendSYNACK(data)
									return
						else:
							if typeTCP & FIN:
								print "in - this is a FIN"
							else:
								if typeTCP & ACK:
									print "in - this is a ACK" + " seq:"+ str(data[TCP].seq) +" ack:"+ str(data[TCP].ack)
									if checkWhiteList(data[IP].src) == 1:
										packet.accept()
										return
									else:
										if isThisToIgnore(data[TCP].seq) == 1: #this is a loopback to the server
											print "*this is a loopback packet"
											removePacketToIgnore(data[TCP].seq)
											packet.accept()
											#time.sleep(100)
											return
										else:
											packet.drop()
											if testCookie(data) == 1:
												#build handshake with server
												print "challenge win starting the handshake"
												setIpTrust(data)
												sendSYN(data)
											else:
												#blackList this IP
												print "challenge fail"
											return
								else:
									if typeTCP & RST:
										print "in - this is a RST"
							
		packet.accept()
	else: # this is what is leaving the server
		if data.haslayer("HTTP"):  #let filter out all the interesting packet
			print "out - this is a HTTP "
		else:
				
			if data.tos == 0:
				typeTCP = data[TCP].flags
				
				if typeTCP & SYN and typeTCP & ACK:
					print "out - this is a SYN ACK" + " seq:" + str(data[TCP].seq) +" ack:"+ str(data[TCP].ack)
					if checkWhiteList(data[IP].dst) == 1:
						packet.accept()
						return
					else:
						packet.drop()
						sendACK(data)
						whiteListIp(data[TCP].ack-1)
						return
				else:
					if typeTCP & FIN and typeTCP & ACK:
						print "out - this is a FIN ACK"
					else:
						if typeTCP & SYN:
							print "out - this is a SYN" + " seq:"+ str(data[TCP].seq) +" ack:"+ str(data[TCP].ack)
						else:
							if typeTCP & FIN:
								print "out - this is a FIN"
							else:
								if typeTCP & ACK:
									print "out - this is a ACK" + " seq:"+ str(data[TCP].seq) +" ack:"+ str(data[TCP].ack)
								else:
									if typeTCP & RST:
										print "out - this is a RST"
		packet.accept()


		
HASH_SEED_SECRET = make_random_password()


nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)


try:
	nfqueue.run()
except KeyboardInterrupt:
    print('')

nfqueue.unbind()