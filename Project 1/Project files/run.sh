#! /bin/bash
clear

echo Program Developed by Umeer Mohammad - Student Code: 4748549
sudo apt-get install libpcap-dev
sudo gcc -o tmpProgram4748549 DnsPacketParser-UmeerM.c -lpcap
sudo ./tmpProgram4748549 $1 $2
sudo rm tmpProgram4748549
echo ----
echo ---
echo -
echo If the operation is successful the json output can be found at: $2
echo Program Developed by Umeer Mohammad - Student Code: 4748549
