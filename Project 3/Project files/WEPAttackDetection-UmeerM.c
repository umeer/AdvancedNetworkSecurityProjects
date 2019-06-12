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



#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN	6
#define MAX_SIZE_ARP_TABLE 2000
#define ETHERTYPE_IP 0x0800
#define SPAM_CRITIC_RIPETITION_VALUE 3
#define SIZE_DATA_CRIPTED 54



struct kickOutLoggerStruct{
  u_char mac_source[25];
  u_char mac_destination[25];
  u_int count;
};

FILE * fOut;

char* pcap_file_name = "file.pcap";
char* output_file_name = "error_log.txt";
int packet_counter;
int kickOutLoggerSize = 0;
struct kickOutLoggerStruct kickOutLogger[MAX_SIZE_ARP_TABLE];
int kickOutLoggerSize2 = 0;
struct kickOutLoggerStruct kickOutLogger2[MAX_SIZE_ARP_TABLE];

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


int kickOutSpamAnalyser(char *mac_sender, char *mac_target){

  int found = 0; // is eqal to 1 when there is a corrispondency in the DB
  int i = 0;

  //Check if that ip is alrady assosiated with a differnet macAddress
  for(i = 0; i<kickOutLoggerSize ; i++){
    if(strcmp(kickOutLogger[i].mac_source, mac_sender)==0 && strcmp(kickOutLogger[i].mac_destination, mac_target)==0){
      found = 1;
      kickOutLogger[i].count ++;
      if(kickOutLogger[i].count>SPAM_CRITIC_RIPETITION_VALUE){
        return kickOutLogger[i].count;
      }
    }
  }

  if(found == 0){
    strcpy(kickOutLogger[kickOutLoggerSize].mac_source, mac_sender);
    strcpy(kickOutLogger[kickOutLoggerSize].mac_destination, mac_target);
    kickOutLogger[kickOutLoggerSize].count = 1;

    kickOutLoggerSize ++;
  }

return 0;
}


int kickOutSpamAnalyserARP(char *mac_sender, char *mac_target){

  int found = 0; // is eqal to 1 when there is a corrispondency in the DB
  int i = 0;

  //Check if that ip is alrady assosiated with a differnet macAddress
  for(i = 0; i<kickOutLoggerSize2 ; i++){
    if(strcmp(kickOutLogger2[i].mac_source, mac_sender)==0 && strcmp(kickOutLogger2[i].mac_destination, mac_target)==0){
      found = 1;
      kickOutLogger2[i].count ++;
      if(kickOutLogger2[i].count>SPAM_CRITIC_RIPETITION_VALUE){
        return kickOutLogger2[i].count;
      }
    }
  }

  if(found == 0){
    strcpy(kickOutLogger2[kickOutLoggerSize2].mac_source, mac_sender);
    strcpy(kickOutLogger2[kickOutLoggerSize2].mac_destination, mac_target);
    kickOutLogger2[kickOutLoggerSize2].count = 1;

    kickOutLoggerSize2 ++;
  }

return 0;
}

struct radiotap_header{
		uint8_t revision;
		uint8_t pad;
		uint16_t lenght;
	};
	struct frame_control_field{
		uint8_t subtype;
		uint8_t flags;

	};
	struct payload{
		uint16_t duration;
		u_char destination[ETHER_ADDR_LEN];
		u_char source[ETHER_ADDR_LEN];
		u_char bssid[ETHER_ADDR_LEN];
		uint16_t data1;
	};
	struct payload_2{
		uint16_t duration;
		u_char receiver[ETHER_ADDR_LEN];
		u_char trasmitter[ETHER_ADDR_LEN];
		u_char destination[ETHER_ADDR_LEN];
		uint16_t seqence_number;
		u_char source[ETHER_ADDR_LEN];
	};

void my_packet_handler
(
  u_char *args,
  const struct pcap_pkthdr *header,
  const u_char *packet
)
{

	//u_char *tmp;
	char errorLog[200]="";


  packet_counter++;

  //PARSING LIMITATOR TEST PHASE
  if(packet_counter>MAX_SIZE_ARP_TABLE){
    return;
  }

  printf("\n\nPacekt Deauth/Disass #[%d]\n", packet_counter);

	struct radiotap_header *radioTapHeader;
	radioTapHeader = (struct radiotap_header *) packet;
	printf("Radio Tap Header: \n revision: %d pad: %d lenght: %d\n",radioTapHeader->revision,radioTapHeader->pad, radioTapHeader->lenght);



	struct frame_control_field *frameControlField;
	frameControlField = (struct frame_control_field *) (packet+radioTapHeader->lenght);
	int subtypeNum= (frameControlField->subtype-(16*(frameControlField->subtype/16)))+frameControlField->subtype/16;
	printf("Frame Control Field: \n subtype: %s flag: %x\n", (subtypeNum==12 ? "Deauthentication" : "Disassociate" ), frameControlField->flags);



	struct payload *payloadData;
	payloadData = (struct payload *) (packet+radioTapHeader->lenght+2);
	char mac_source[25], mac_destination[25], mac_bssid[25];
	hexStringToStringMAC(payloadData->source, mac_source);
	hexStringToStringMAC(payloadData->destination, mac_destination);
	hexStringToStringMAC(payloadData->bssid, mac_bssid);
	printf("Payload:\n duration:%d destination: %s source:%s bssid:%s sequence num:%d fragment num:%d\n", payloadData->duration, mac_destination,mac_source, mac_bssid, calculateSequenceNumber(payloadData->data1), calculateFragmentNumber(payloadData->data1));


	int kickSpamCounter =  kickOutSpamAnalyser(mac_source, mac_destination);
	if(kickSpamCounter!=0){
		printf("Warning there is a possible attack (Deauth or Disass), multiple packets have been found  {#%d}\n",kickSpamCounter);
	    strcpy(errorLog,"Warning there is a possible attack (Deauth or Disass), multiple packets have been found");
	}



	if(strlen(errorLog)!=0){
	    fprintf(fOut, "\"#%d\",\"%d\",\"%d\",\"%d\",\"%s\",\"0x%x\",\"%d\",\"%s\",\"%s\",\"%s\",\"%d\",\"%d\",\"error: %s\" \n", packet_counter, radioTapHeader->revision, radioTapHeader->pad, radioTapHeader->lenght, (subtypeNum==12 ? "Deauthentication" : "Disassociate" ), frameControlField->flags, payloadData->duration, mac_destination,mac_source, mac_bssid, calculateSequenceNumber(payloadData->data1), calculateFragmentNumber(payloadData->data1), errorLog);
	  }



  return;

    //TESTING
	//tmp = (u_char *)(packet+radioTapHeader->lenght);
	//printf("data: %x\n", ntohs(*(uint32_t *)tmp));

}


void my_packet_handler_2
(
  u_char *args,
  const struct pcap_pkthdr *header,
  const u_char *packet
)
{
	char errorLog[200]="";

	if (header->len > 150){ // this is not a arp, too big
		return;
	}

	struct radiotap_header *radioTapHeader;
	radioTapHeader = (struct radiotap_header *) packet;


	struct frame_control_field *frameControlField;
	frameControlField = (struct frame_control_field *) (packet+radioTapHeader->lenght);
	int subtypeNum= (frameControlField->subtype-(16*(frameControlField->subtype/16)))+frameControlField->subtype/16;


	int body_size = 0;
	if(frameControlField->flags == 67){
		body_size = 38;
	}else if(frameControlField->flags == 65){
		body_size = 32;
	}else{
		return;
	}

	int delta_size = header->len - body_size - radioTapHeader->lenght;
	if(delta_size != SIZE_DATA_CRIPTED){
		return;
	}

	struct payload_2 *payloadData;
	payloadData = (struct payload_2 *) (packet+radioTapHeader->lenght+2);
	char mac_source[25], mac_destination[25], mac_bssid[25];
	if(frameControlField->flags == 67){
		hexStringToStringMAC(payloadData->source, mac_source);
		hexStringToStringMAC(payloadData->destination, mac_destination);
		hexStringToStringMAC(payloadData->trasmitter, mac_bssid);
	}else if(frameControlField->flags == 65){
		hexStringToStringMAC(payloadData->trasmitter, mac_source);
		hexStringToStringMAC(payloadData->destination, mac_destination);
		hexStringToStringMAC(payloadData->receiver, mac_bssid);
	}

	packet_counter++;

	//PARSING LIMITATOR TEST PHASE
	if(packet_counter>MAX_SIZE_ARP_TABLE){
		return;
	}
	printf("\n\nPacekt ARP #[%d] size: %d\n", packet_counter, header->len);

	printf("Radio Tap Header: \n revision: %d pad: %d lenght: %d\n",radioTapHeader->revision,radioTapHeader->pad, radioTapHeader->lenght);

	printf("Frame Control Field: \n subtype: %d flag: %x\n", subtypeNum, frameControlField->flags);

	printf("Payload:\n duration:%d destination: %s source:%s bssid:%s sequence num:%d fragment num:%d\n", payloadData->duration, mac_destination, mac_source, mac_bssid, calculateSequenceNumber(payloadData->seqence_number), calculateFragmentNumber(payloadData->seqence_number));

	int kickSpamCounter =  kickOutSpamAnalyser(mac_source, mac_destination);
	if(kickSpamCounter!=0){
		printf("Warning there is a possible attack arp, multiple packets have been found  {#%d}\n",kickSpamCounter);
	    strcpy(errorLog,"Warning there is a possible attack (arp), multiple packets have been found");
	}


	if(strlen(errorLog)!=0){
	    fprintf(fOut, "\"#%d\",\"%d\",\"%d\",\"%d\",\"%d\",\"0x%x\",\"%d\",\"%s\",\"%s\",\"%s\",\"%d\",\"%d\",\"error: %s\" \n", packet_counter, radioTapHeader->revision, radioTapHeader->pad, radioTapHeader->lenght, subtypeNum, frameControlField->flags, payloadData->duration, mac_destination,mac_source, mac_bssid, calculateSequenceNumber(payloadData->seqence_number), calculateFragmentNumber(payloadData->seqence_number), errorLog);
	  }

  return;

    //TESTING
	//tmp = (u_char *)(packet+radioTapHeader->lenght);
	//printf("data: %x\n", ntohs(*(uint32_t *)tmp));

}



int main(int argc, char *argv[]){
  pcap_t *handle, *handle2;			/* Session handle */
  char error_buffer[PCAP_ERRBUF_SIZE];	/* Error string */
  struct bpf_program filter, filter2;
  char *filter_desc ="type mgt subtype deauth or subtype disassoc";
  char *filter_desc_2 ="";
  int link_type;


  printf("Developed by Umeer Mohammad - Student Code: 4748549\n");



  if(argc !=3){
   /printf("Please provide the address to |pcapfile.pcap|output.txt\n");
   return 1;
  }

   pcap_file_name = argv[1];
   output_file_name = argv[2];



	 fOut = fopen (output_file_name,"w");
	 fprintf(fOut, "packet_counter, mac_destination, mac_source, type, hardware type, protocol type, hardware size, protocol size,  opcode, mac_sender, ip_sender, mac_target, ip_target, error definition\n");



	/* Open device for live capture */
	handle = pcap_open_offline(pcap_file_name, error_buffer);
	if (handle == NULL) {
	fprintf(stderr, "I can´t not open the file.\n");
	return 2;
	}


	link_type = pcap_datalink(handle);

	if (link_type != DLT_LINUX_SLL && link_type != DLT_EN10MB &&
	link_type != DLT_IPV4 && link_type != DLT_IPV6 && link_type != DLT_IEEE802_11_RADIO) {
	  fprintf(stderr, "Unsupported link type: %d\n", link_type);
	  return 2;
	}


    //Packet filtering keep only ARP
    if(pcap_compile(handle, &filter, filter_desc, 0, 0) == -1  || pcap_setfilter(handle, &filter)==-1){
      fprintf(stderr, "Bad filter - %s\n", pcap_geterr(handle));
      return 2;
    }

    packet_counter = 0;
    pcap_loop(handle, 0, my_packet_handler, NULL);

    pcap_close(handle);







    handle2 = pcap_open_offline(pcap_file_name, error_buffer);
     if (handle2 == NULL) {
       fprintf(stderr, "I can´t not open the file.\n");
       return 2;
     }


     link_type = pcap_datalink(handle2);

      if (link_type != DLT_LINUX_SLL && link_type != DLT_EN10MB &&
       link_type != DLT_IPV4 && link_type != DLT_IPV6 && link_type != DLT_IEEE802_11_RADIO) {
         fprintf(stderr, "Unsupported link type: %d\n", link_type);
         return 2;
       }


    //Packet filtering keep only ARP
	if(pcap_compile(handle2, &filter2, filter_desc_2, 0, 0) == -1  || pcap_setfilter(handle2, &filter2)==-1){
	  fprintf(stderr, "Bad filter - %s\n", pcap_geterr(handle2));
	  return 2;
	}

	packet_counter = 0;
	pcap_loop(handle2, 0, my_packet_handler_2, NULL);

    pcap_close(handle2);




    fclose(fOut);


    return(0);
  }
