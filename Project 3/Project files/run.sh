#! /bin/bash
clear

sudo apt-get install libpcap-dev
echo
sudo gcc -o tmpProgram4748549 WEPAttackDetection-UmeerM.c -lpcap
#sudo chmod 777 $1
sudo ./tmpProgram4748549 $1 $2
sudo rm tmpProgram4748549
