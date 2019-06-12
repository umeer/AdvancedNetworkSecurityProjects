#!/usr/bin/env python
from netfilterqueue import NetfilterQueue
import threading, time, os

from scapy.config import conf
from scapy.supersocket import L3RawSocket
from scapy.all import *
import scapy_http.http



HASH_SEED = "Ciao Mondo"

INTERFACE_NAME  = "enp0s3"


listIpToConfirm = []
requestedSite = []

listIpSecure = []


def make_random_password():
	return ''+str(os.urandom(16))


def isNew(packet):
	for i in range (len(listIpToConfirm)):
		if listIpToConfirm[i] == packet['IP'].src:
			return 0
	return 1

def getRequestedSite (packet):
	for i in range (len(listIpToConfirm)):
		if listIpToConfirm[i] == packet['IP'].src:
			return requestedSite[i]
	
def removeIp(packet):
	for i in range (len(listIpToConfirm)):
		if listIpToConfirm[i] == packet['IP'].src:
			listIpToConfirm.pop(i)
			requestedSite.pop(i)
				
def isSecure(packet):
	for i in range (len(listIpSecure)):
		if listIpSecure[i] == packet['IP'].src:
			return 1
	return 0
	
def buildChallengeRequestSite(packet):
	return "/?"+str(hash(packet['IP'].src + HASH_SEED))
	


def sendRedirectionPacket(pkt, redirectionSite):
	conf.L3socket = L3RawSocket
	info = "HTTP/1.1 302 Found\r\nLocation: " + redirectionSite + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	resp_http = IP(src=pkt['IP'].dst, dst=pkt['IP'].src)/TCP(sport=pkt['TCP'].dport, dport=pkt['TCP'].sport, flags="PA", seq=pkt['TCP'].ack , ack=pkt['TCP'].seq + (pkt['IP'].len - 52))
	send(resp_http/Raw(load=info),iface=INTERFACE_NAME)
	


def print_and_accept(packet):

	data = IP(packet.get_payload())	
	
	if data.haslayer("HTTP") and data["HTTP"].Method == "GET":  #let filter out all the interesting packet
	
		print  "method: "+ data["HTTP"].Method + " path: "+ data["HTTP"].Path 
		
		if  isSecure(data) == 1:#The ip is trusted
			print "is now secure"
			packet.accept();
			return
		else:
			if isNew(data) == 1: #This is the first time that i see this packet
				print "never saw this ip"
				listIpToConfirm.append(data[IP].src)
				requestedSite.append(data["HTTP"].Path)
				sendRedirectionPacket(data, buildChallengeRequestSite(data))				
			else:
				print "ip already seen" # This is the second time i see a GET req
				if data["HTTP"].Path == buildChallengeRequestSite(data):
					print "redirection successful"
					listIpSecure.append(data[IP].src)
					sendRedirectionPacket(data, getRequestedSite(data))
					removeIp(data)
			packet.drop()
			return
				
	packet.accept()

HASH_SEED = make_random_password()



nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)


try:
	nfqueue.run()
except KeyboardInterrupt:
    print('')

nfqueue.unbind()