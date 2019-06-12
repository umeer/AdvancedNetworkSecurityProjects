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
#include <math.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <netinet/ip6.h>


#define SIZE_LIMITER 1000000
#define SIZE_ETHERNET 14
//#define ETHER_ADDR_LEN	6
#define MAX_SIZE_ARP_TABLE 2000
#define ETHERTYPE_IP 0x0800
#define SPAM_CRITIC_RIPETITION_VALUE 3
#define SIZE_DATA_CRIPTED 54


char* pcap_file_name = "file.pcap";

int packet_counter =0;



void intToStringIP(int ip, char * string_ip){
  char string_value[25];
  unsigned char bytes[4];
  bytes[0] = ip & 0xFF;
  bytes[1] = (ip >> 8) & 0xFF;
  bytes[2] = (ip >> 16) & 0xFF;
  bytes[3] = (ip >> 24) & 0xFF;
  sprintf(string_value,"%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
  memcpy(string_ip,string_value, sizeof(string_value));
}


void  hexStringToStingIp(const char* ipAddress, char * string_ip) {
  char string_value[25];
  sprintf(string_value,"%d.%d.%d.%d", ipAddress[0]& 0xFF, ipAddress[1]& 0xFF, ipAddress[2]& 0xFF, ipAddress[3]& 0xFF);
  memcpy(string_ip,string_value, sizeof(string_value));
}


void hexStringToStringMAC(const char* macAddress, char * result){
  char string_value[25];
  sprintf(string_value,"%02x:%02x:%02x:%02x:%02x:%02x", macAddress[0]& 0xFF, macAddress[1]& 0xFF, macAddress[2]& 0xFF, macAddress[3]& 0xFF, macAddress[4]& 0xFF, macAddress[5]& 0xFF);
  memcpy(result, string_value, sizeof(string_value));

}

int calculateSequenceNumber(int n){
	int sequenceNumber =0;
	if((n >> 15)&1){
		sequenceNumber += 2048;
	}
	if((n >> 14)&1){
			sequenceNumber += 1024;
		}
	if((n >> 13)&1){
			sequenceNumber += 512;
		}
	if((n >> 12)&1){
			sequenceNumber += 256;
		}
	if((n >> 11)&1){
			sequenceNumber += 128;
		}
	if((n >> 10)&1){
			sequenceNumber += 64;
		}
	if((n >> 9)&1){
			sequenceNumber += 32;
		}
	if((n >> 8)&1){
			sequenceNumber += 16;
		}
	if((n >> 7)&1){
			sequenceNumber += 8;
		}
	if((n >> 6)&1){
			sequenceNumber += 4;
		}
	if((n >> 5)&1){
			sequenceNumber += 2;
		}
	if((n >> 4)&1){
			sequenceNumber += 1;
		}
	return sequenceNumber;
}
int calculateFragmentNumber(int n){
	int number =0;

		if((n >> 3)&1){
			number += 8;
			}
		if((n >> 2)&1){
			number += 4;
			}
		if((n >> 1)&1){
			number += 2;
			}
		if((n >> 0)&1){
			number += 1;
			}
		return number;
}

char* cleanResult(char *str) {

	str = strchr(str, '=')+1;
	str[strlen(str)-1] = '\0';

    return str;
}

char *database[50];
char *databaseA[50];

char *database2[50];

int dbSize = 14;

int tagSniffer (char *line){

	int i= 0;

	for (i = 0; i<dbSize; i++){
		if(strstr(line, database[i]) != NULL){
			//printf("this line is present%s",line);
			return i;
		}
	}


	for (i = 0; i<dbSize; i++){
			if(strstr(line, databaseA[i]) != NULL){
				//printf("this line is present%s",line);
				return i;
			}
		}




	return -1;
}



struct DataParse {
        u_char  source[20];    /* destination host address */
        u_char source_port[20];
        u_char  dest[20];    /* source host address */
        u_char dest_port[20];
        int numberTag;
        int tag[100];
};

struct Matrix {
		u_char  source[20];    /* destination host address */
		u_char source_port[20];
		u_char  dest[20];    /* source host address */
		u_char dest_port[20];
		float table[15][15];
		int last_tag;

};


char *RAW_DATA_FILE = "rawData.txt";
char *OUTPUT_GRAPH_FILE = "graph.dot";
char *OUTPUT_TABLE_FILE = "tableDataOutput.txt";
char *OUTPUT_LOG_FILE = "logDataOutput.txt";



FILE * fp, *fOutGraph,*fOutLog, *fOutTable;
struct DataParse dataParseLog[SIZE_LIMITER];
struct Matrix matrix[SIZE_LIMITER];

int dataParseLogSize = 0, matrixSize = 0;
char *target = "#################", *target2 ="\n";
char *targetSource = "src",*targetSourcePort = "sport", *targetDest = "dst", *targetDestPort = "dport";



int findMatrix( char *sip, char *sport, char *dip, char *dport){

	int k = 0;
	for(k=0; k<matrixSize; k++){
		if((strcmp(matrix[k].dest,dip)==0 && strcmp(matrix[k].source,sip)==0) || (strcmp(matrix[k].dest,sip)==0 && strcmp(matrix[k].source,dip)==0)){ //Only ip comparision because the port may change
			return k;
		}
	}

	return -1;
}

void prepareMatrixTable (int size){
	int i=0, j =0;

	for(i=0; i<13; i++){
		for (j=0; j<12; j++){
			matrix[size].table[i][j]=0;
		}
	}

}


int main(int argc, char *argv[]){

	char * line = NULL;
	size_t len = 0;
	ssize_t read;

	database[0] ="start";//
	database[1] ="content_type= hello_request";//
	database[2] ="content_type= client_hello";
	database[3] ="type      = server_hello";
	database[4] ="type      = certificate";
	database[5] ="type      = server_key_exchange";//
	database[6] ="type      = certificate_request";//
	database[7] ="type      = server_hello_done";
	database[8] ="type      = certificate_verify";//
	database[9] ="type      = client_key_exchange";
	database[10] ="type      = finished";//
	database[11] ="content_type= change_cipher_spec";
	database[12] ="content_type= application_data";
	database[13] ="content_type= alert";
	database[14] ="end";//



	databaseA[0] ="start";//
	databaseA[1] ="content_type= hello_request";//
	databaseA[2] ="type      = client_hello";
	databaseA[3] ="type      = server_hello";
	databaseA[4] ="type      = certificate";
	databaseA[5] ="type      = server_key_exchange";//
	databaseA[6] ="type      = certificate_request";//
	databaseA[7] ="type      = server_hello_done";
	databaseA[8] ="type      = certificate_verify";//
	databaseA[9] ="type      = client_key_exchange";
	databaseA[10] ="type      = finished";//
	databaseA[11] ="content_type= change_cipher_spec";
	databaseA[12] ="application_data";
	databaseA[13] ="content_type= alert";
	databaseA[14] ="end";//






	database2[0] ="start";//
	database2[1] ="hello_request";//
	database2[2] ="client_hello";
	database2[3] ="server_hello";
	database2[4] ="certificate";
	database2[5] ="server_key_exchange";//
	database2[6] ="certificate_request";//
	database2[7] ="server_hello_done";
	database2[8] ="certificate_verify";//
	database2[9] ="client_key_exchange";
	database2[10] ="finished";//
	database2[11] ="change_cipher_spec";
	database2[12] ="application_data";
	database2[13] ="alert";
	database2[14] ="end";//



	printf("Data Analyzer by Umeer Mohammad - Student Code: 4748549\n");


	//READ DATA FROM FILE
    printf("\n\n==================>  Data Parsing&Filtration <=====================\n");

	fp = fopen(RAW_DATA_FILE, "r");
	fOutLog = fopen(OUTPUT_LOG_FILE, "w");


	if (fp == NULL){
		printf("I can't find the raw data file.\n");
		return(1);
	}

	 fprintf(fOutLog, "ip_destination	port_destination	ip_source	port_source	handshake\n");


	 while ((read = getline(&line, &len, fp)) != -1) {

	        //printf("Retrieved line of length %zu :\n", read);

	        if(strstr(line,target) != NULL) {
		        printf("\n%s", line);
		        struct DataParse dataParse;
		        dataParse.numberTag = 0;
	    		 while ((read = getline(&line, &len, fp)) != -1 && strcmp(line, target2)!=0) {
	    			 if(strstr(line,targetSource) != NULL){
	    				 strcpy(dataParse.source, cleanResult(line));
	    			 }else if(strstr(line,targetDest) != NULL){
						 strcpy(dataParse.dest, cleanResult(line));
					 }else if(strstr(line,targetSourcePort) != NULL){
						 strcpy(dataParse.source_port, cleanResult(line));
					 }else if(strstr(line,targetDestPort) != NULL){
						 strcpy(dataParse.dest_port, cleanResult(line));
					 }else if(tagSniffer(line)!=-1){
						 dataParse.tag[dataParse.numberTag] = tagSniffer(line);
						 dataParse.numberTag = dataParse.numberTag + 1;
						 printf(" handshake detected: %s\n", cleanResult(line));
						 fprintf(fOutLog, "%s	%s	%s	%s	%s\n",dataParse.dest, dataParse.dest_port, dataParse.source, dataParse.source_port, database2[tagSniffer(line)] );
					 }
	    		 }

	    		 if(dataParse.numberTag >0){
	  		        printf("%s %s %s %s\n", dataParse.dest, dataParse.dest_port, dataParse.source, dataParse.source_port);
					strcpy(dataParseLog[dataParseLogSize].dest, dataParse.dest);
					strcpy(dataParseLog[dataParseLogSize].dest_port, dataParse.dest_port);
					strcpy(dataParseLog[dataParseLogSize].source, dataParse.source);
					strcpy(dataParseLog[dataParseLogSize].source_port, dataParse.source_port);
					dataParseLog[dataParseLogSize].numberTag = dataParse.numberTag;

					int j=0;
					for(j=0; j<dataParse.numberTag; j++){
						dataParseLog[dataParseLogSize].tag[j]=dataParse.tag[j];
					}

	    		     dataParseLogSize ++;
	    		 }
	        }
	    }
    fclose(fp);
    fclose(fOutLog);

    //DATA ANALY
    printf("\n\n==================>  Tables Creation <=====================\n");

    if(dataParseLogSize==0){
     	printf("No handshake found");
     	return 0;
     }

    int i=0;
    for(i =0; i < dataParseLogSize; i++){
    	int j=0;
    	for(j=0; j<dataParseLog[i].numberTag; j++){
    		int newTag = dataParseLog[i].tag[j];

			int matrixID = findMatrix(dataParseLog[i].source, dataParseLog[i].source_port, dataParseLog[i].dest, dataParseLog[i].dest_port);
			if(matrixID !=-1){
				printf("table #%d found for %s and %s\n", matrixID, dataParseLog[i].source, dataParseLog[i].dest);
				if(newTag == 1 || newTag ==2){//new session "hello_request" "client_hello"
					matrix[matrixID].table[matrix[matrixID].last_tag][14]++;
					matrix[matrixSize].table[0][newTag] ++;
					matrix[matrixID].last_tag = newTag;
				}else{
					matrix[matrixID].table[matrix[matrixID].last_tag][newTag]++;
					matrix[matrixID].last_tag = newTag;
				}
			}else{
				//create a new table
				printf("table #%d creation for %s and %s\n", matrixSize, dataParseLog[i].source, dataParseLog[i].dest);
				prepareMatrixTable(matrixSize);
				strcpy(matrix[matrixSize].dest, dataParseLog[i].dest);
				strcpy(matrix[matrixSize].dest_port, dataParseLog[i].dest_port);
				strcpy(matrix[matrixSize].source, dataParseLog[i].source);
				strcpy(matrix[matrixSize].source_port, dataParseLog[i].source_port);
				matrix[matrixSize].table[0][newTag] ++;
				matrix[matrixSize].last_tag = newTag;
				matrixSize ++;
			}
    	}
    }



    //MATRIX NORMALIZZATION
    i=0;
   for(i=0; i<matrixSize; i++){
	int x=0, y=0;

	for(x=0; x<15; x++){
		float totalRow=0;
		for(y=0; y<15; y++){
			totalRow = totalRow + matrix[i].table[x][y];
		}

		for(y=0; y<15; y++){
			float result = matrix[i].table[x][y]/totalRow;
			if(totalRow==0) result =0;

			 matrix[i].table[x][y] = result;
		}
	 }
   }





    printf("\n\n==================>  Tables PrintOut <=====================\n");

     fOutTable = fopen(OUTPUT_TABLE_FILE, "w");
	 fOutGraph = fopen (OUTPUT_GRAPH_FILE,"w");


    i=0;
    for(i=0; i<matrixSize; i++){
    	printf("\nTable: #%d\n", i);
    	fprintf(fOutGraph, "digraph G%d{\n",i);
     	fprintf(fOutTable, "Table: #%d\n",i);


    	int x=0, y=0;
        for(x=0; x<15; x++){
            for(y=0; y<15; y++){
            	printf("%.0f ", matrix[i].table[x][y]*100);
             	fprintf(fOutTable, "%.0f ", matrix[i].table[x][y]*100);

            	if(matrix[i].table[x][y]!=0){
                	fprintf(fOutGraph, " %s -> %s[label=\"%.0f\",weight=\"%.0f\"];\n", database2[x], database2[y], matrix[i].table[x][y]*100, matrix[i].table[x][y]*100);
            	}
            }
            printf("\n");
         	fprintf(fOutTable, "\n");

        }
    	fprintf(fOutGraph, "}\n");
     	fprintf(fOutTable, " ");
    }

    fclose(fOutGraph);
    fclose(fOutTable);






    return(0);
  }
