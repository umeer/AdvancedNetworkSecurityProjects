import sys
from StringIO import StringIO
import scapy
#from scapy.layers.ssl_tls import *
from scapy_ssl_tls.ssl_tls import *
import socket

textTracer = "###[ SSL/TLS ]###"

inputFileName = "testing.pcap"
outFileName = "rawData.txt"

print("Data Parser by Umeer Mohammad - Student Code: 4748549\n")


if len(sys.argv) != 2:
	print("Warning: The pcap file is not specified hence the testing.pcap will be automatically used...\n")

if len(sys.argv) == 2:	
	inputFileName = sys.argv[1];


print ("==================>  Data Parsing Stage 1 <=====================")

file = open(outFileName,"w") 


packets = rdpcap(inputFileName)
counter = 1
for packet in packets:
	print("Packet Parsed", counter)
	
	capture = StringIO()
	save_stdout = sys.stdout
	sys.stdout = capture
	print("################# this is a packet ", counter)	
	packet.show()
	print("")
	sys.stdout = save_stdout
	string = capture.getvalue()
	
	if textTracer in string:
		file.write(string)
	
	counter = counter +1
	
	#if counter ==15:
		#exit()


file.close() 
		