#! /bin/bash
clear

sudo apt-get install libpcap-dev
echo
sudo gcc -o tmpProgram4748549 ARPParser-UmeerM.c -lpcap
sudo chmod 777 $1
sudo ./tmpProgram4748549  $1 $2 $3
sudo rm tmpProgram4748549
