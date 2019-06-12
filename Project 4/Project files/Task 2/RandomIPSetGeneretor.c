#include <pcap.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <netinet/in.h>
#include <string.h>

#define SIZEIpset 40
#define SIZE 50000


FILE * fOut;
char* file = "fileRule2";


int main(int argc, char *argv[]){

	fOut = fopen (file,"w");


	int j=0;
	for(j=0; j<SIZEIpset;j++){

		fprintf(fOut, "create myset%d hash:ip family inet hashsize 1024 maxelem 65536\n",j);

		int i = 0;
		int two=0;
		int three=0;

		for(i = 0; i<SIZE; i++){
			fprintf(fOut,  "add myset%d 1.%d.%d.%d\n",j,j,two,three);

			three ++;
			if(three >255){
				three =0;
				two ++;
			}
		}
	}







	fclose(fOut);


	return(0);
  }
