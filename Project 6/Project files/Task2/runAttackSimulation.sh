#! /bin/bash
clear

sudo apt-get update

sudo apt-get install python-scapy
sudo apt install python-pip
sudo -H pip install --upgrade pip
sudo -H pip install scapy-ssl_tls
sudo apt-get install libpcap-dev



sudo apt-get install build-essential python-dev libnetfilter-queue-dev
sudo pip install NetfilterQueue

sudo iptables -F

sudo python attackSimulation.py

