#! /bin/bash
clear

apt-get update
sudo apt-get install python-scapy
sudo apt install python-pip
sudo -H pip install --upgrade pip
sudo -H pip install scapy-ssl_tls
sudo apt install graphviz

#sudo apt-get install libpcap-dev
	
python ./python_data_reader.py $1
echo
sudo gcc -o tmpProgram4748549 Task3-UmeerM.c -lm
sudo ./tmpProgram4748549 
sudo rm tmpProgram4748549
dot -Tps graph.dot -o imageGraph.ps