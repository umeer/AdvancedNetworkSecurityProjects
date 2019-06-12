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




struct sniff_ethernet{
  u_char ether_dhost[ETHER_ADDR_LEN];
  u_char ether_shost[ETHER_ADDR_LEN];
  u_short ether_type;
};


struct sniff_ARP{
  uint16_t htype;
  uint16_t ptype;
  uint8_t hsize;
  uint8_t psize;
  uint16_t opcode;
  u_char mac_sender[ETHER_ADDR_LEN];
  u_char ip_sender[4];
  u_char mac_target[ETHER_ADDR_LEN];
  u_char ip_target[4];
};


struct sniff_tcp{
  u_short sport;
  u_short dport;
  u_int seq;
  u_int ack;
  u_char hlrs;
  u_char flags;
  u_short win;
  u_short sum;
  u_short urp;
};

struct arp_tupla{
  u_char ip[25];
  u_char mac[25];
};

struct arp_complete_tupla{
  u_char ip_sender[25];
  u_char mac_sender[25];
  u_char ip_target[25];
  u_char mac_target[25];
  u_int count;
};



char* pcap_file_name = "file.pcap";
char* output_file_name = "output.txt";
char* database_file_name = "database.txt";

int packet_counter;
FILE *fOut;

int sizeArpTable = 0;
struct arp_tupla arpTable[MAX_SIZE_ARP_TABLE];
int sizeArpCompleteTable = 0;
struct arp_complete_tupla arpCompleteTable[MAX_SIZE_ARP_TABLE];



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


int analyseARP(char *ip, char *mac){

  int found = 0; // is eqal to 1 when there is a corrispondency in the DB
  int i = 0;

  //Check if that ip is alrady assosiated with a differnet macAddress
  for(i =0; i<sizeArpTable ; i++){
    if(strcmp(arpTable[i].ip, ip)==0){
      found =1;
      if(strcmp(arpTable[i].mac, mac)==0){
        //All good
        printf(" >configuration already present in database\n");
      }else{
        // This ip is already assosiated with another macAddress
        printf(" >the ip is already been used by another mac address\n");
        goto reportError;
      }
    }
  }

  if(found == 0){
    printf(" >configuration saved in the database\n");
    strcpy(arpTable[sizeArpTable].ip, ip);
    strcpy(arpTable[sizeArpTable].mac, mac);
    sizeArpTable ++;
  }


  return 0;

reportError:
  return 1;
}


int spamAnalyser(char *ip_sender, char *mac_sender, char *ip_target, char *mac_target){

  int found = 0; // is eqal to 1 when there is a corrispondency in the DB
  int i = 0;

  //Check if that ip is alrady assosiated with a differnet macAddress
  for(i = 0; i<sizeArpCompleteTable ; i++){
    if(strcmp(arpCompleteTable[i].ip_sender, ip_sender)==0 && strcmp(arpCompleteTable[i].mac_sender, mac_sender)==0 && strcmp(arpCompleteTable[i].ip_target, ip_target)==0 && strcmp(arpCompleteTable[i].mac_target, mac_target)==0){
      found = 1;
      arpCompleteTable[i].count ++;
      if(arpCompleteTable[i].count>SPAM_CRITIC_RIPETITION_VALUE){
        return 1;
      }
    }
  }

  if(found == 0){
    strcpy(arpCompleteTable[sizeArpCompleteTable].ip_sender, ip_sender);
    strcpy(arpCompleteTable[sizeArpCompleteTable].mac_sender, mac_sender);
    strcpy(arpCompleteTable[sizeArpCompleteTable].ip_target, ip_target);
    strcpy(arpCompleteTable[sizeArpCompleteTable].mac_target, mac_target);
    arpCompleteTable[sizeArpCompleteTable].count = 1;

    sizeArpCompleteTable ++;
  }

return 0;
}


void my_packet_handler
(
  u_char *args,
  const struct pcap_pkthdr *header,
  const u_char *packet
)
{

  const struct sniff_ethernet *ethernet;
  const struct sniff_ARP *arpData;
  char errorLog[200]="";

  packet_counter++;

  //PARSING LIMITATOR TEST PHASE
  if(packet_counter>MAX_SIZE_ARP_TABLE){
    return;
  }


  printf("\n\nPacekt #[%d]\n", packet_counter);

  //print Ehternet Header
  ethernet = (struct sniff_ethernet *)(packet);
  char mac_source[25], mac_destination[25];
  int type;
  hexStringToStringMAC(ethernet->ether_shost, mac_source);
  printf("mac source: %s\n", mac_source);
  hexStringToStringMAC(ethernet->ether_dhost, mac_destination);
  printf("mac destination: %s\n", mac_destination);
  type = ntohs(ethernet->ether_type& 0xfff);
  printf("header type: 0x%x\n",type);
  if(ntohs(ethernet->ether_type& 0xfff) != 0X806){
    strcpy(errorLog,"This packet is not ARP (ETH header type !=0x806)");
  }

  //print payload
  arpData= (struct sniff_ARP*)(packet + SIZE_ETHERNET);
  printf("info htype: %d\n", ntohs(arpData->htype));
  printf("info ptype: 0x%x\n", ntohs(arpData->ptype));
  printf("info hsize: %d\n", arpData->hsize & 0xff);
  printf("info psize: %d\n", arpData->psize & 0xff);
  printf("info opcode: %d\n", ntohs(arpData->opcode));
  if(ntohs(arpData->opcode)!= 1 && ntohs(arpData->opcode)!= 2 ){
    strcpy(errorLog,"The opcode of the payload must be 1 or 2 (RFC826)");
  }
  if(ntohs(arpData->opcode)== 1 && strcmp(mac_destination,"ff:ff:ff:ff:ff:ff")!=0  ){
    strcpy(errorLog,"In a requent ARP packet the destination must be broadcast");
  }

  char mac_sender[25];
  hexStringToStringMAC(arpData->mac_sender, mac_sender);
  printf("mac sender: %s\n", mac_sender);
  char ip_sender[25];
  hexStringToStingIp(arpData->ip_sender, ip_sender);
  printf("ip sender: %s\n", ip_sender);
  if(analyseARP(ip_sender, mac_sender) ==1){
    strcpy(errorLog,"The ip address of the sender is already been associated with another mac address");
   }

  char mac_target[25];
  hexStringToStringMAC(arpData->mac_target, mac_target);
  printf("mac target:%s\n", mac_target);
  char ip_target[25];
  hexStringToStingIp(arpData->ip_target, ip_target);
  printf("ip target: %s\n", ip_target);

  if(ntohs(arpData->opcode)== 1 && strcmp(mac_target,"00:00:00:00:00:00")!=0){
    strcpy(errorLog,"In a requent ARP packet the target mac address  must be 00:00:00:00:00:00");
  }else if(ntohs(arpData->opcode)== 2 && strcmp(mac_target,"00:00:00:00:00:00")==0){
    strcpy(errorLog,"The mac address has not been configured");
  }else if(strcmp(mac_target,"00:00:00:00:00:00")!=0){
    if(analyseARP(ip_target, mac_target) ==1){
      strcpy(errorLog,"The ip address of the target is already been associated with a mac address");
     }
  }

  if(spamAnalyser(ip_sender, mac_sender, ip_target, mac_target)==1){
    strcpy(errorLog,"This packet compared mutiple times");
  }


  if(strlen(errorLog)!=0){
    printf("Error: the packet #[%d] is invalid Description: %s\n", packet_counter, errorLog);
    fprintf(fOut, "\"#%d\",\"%s\",\"%s\",\"0x%x\",\"%d\",\"0x%x\",\"%d\",\"%d\",\"%d\",\"%s\",\"%s\",\"%s\",\"%s\",\"error: %s\"\n", packet_counter, mac_destination, mac_source, type, ntohs(arpData->htype), ntohs(arpData->ptype), arpData->hsize & 0xff, arpData->psize & 0xff,  ntohs(arpData->opcode), mac_sender, ip_sender, mac_target, ip_target, errorLog);
    return;
  }

  return;

}



void loadARPTable(){

  printf("Loading data from config file\n");

  char * line = NULL;
  size_t len =0;
  ssize_t read;
  char ip[25]="", mac[25]="";
  char *tmp;


  FILE *fDb = fopen (database_file_name,"r");
  if(fDb == NULL)
  return;

  while ((read = getline(&line, &len, fDb))!= -1) {
    //printf("line read: %s\n", line);
    if(len >0){
      tmp = strchr(line,' ');
      if(tmp != NULL){
        *tmp = '\0';
        strcpy(ip,line);
        strcpy(mac, tmp+1);
        //remove the \n charachter
        size_t ln = strlen(mac)-1;
        if(*mac && ln>0 && mac[ln]=='\n')
        mac[ln] = '\0';
        //Storing value in the arpTable
        strcpy(arpTable[sizeArpTable].ip, ip);
        strcpy(arpTable[sizeArpTable].mac, mac);
        printf("  ip: %s mac: %s\n",  arpTable[sizeArpTable].ip,   arpTable[sizeArpTable].mac );
        sizeArpTable ++;
      }
      tmp = NULL;
    }
    len = 0;
  }

  if(line)
  free(line);

  fclose(fDb);
}

void storeARPTable (){
  //return; //TESTING

  FILE *fDb = fopen (database_file_name,"w");
  int i = 0;
  //Check if that ip is alrady assosiated with a differnet macAddress
  for(i =0; i<sizeArpTable ; i++){
    fprintf(fDb, "%s %s\n", arpTable[i].ip, arpTable[i].mac);
  }

  fclose(fDb);
}



int main(int argc, char *argv[]){
  pcap_t *handle;			/* Session handle */
  char error_buffer[PCAP_ERRBUF_SIZE];	/* Error string */
  struct bpf_program filter;
  char *filter_desc ="arp";
  int link_type;


  printf("ARP Parser and Filter by Umeer Mohammad - Student Code: 4748549\n");

  if(argc !=4){
    printf("Please provide the address to config file|pcapfile.pcap|output.txt\n");
   return 1;
  }

  database_file_name = argv[1];
  pcap_file_name = argv[2];
  output_file_name = argv[3];


  /* Open device for live capture */
  handle = pcap_open_offline(pcap_file_name, error_buffer);
  if (handle == NULL) {
    fprintf(stderr, "I can´t not open the file.\n");
    return 2;
  }


  link_type = pcap_datalink(handle);
  if (link_type != DLT_LINUX_SLL && link_type != DLT_EN10MB &&
    link_type != DLT_IPV4 && link_type != DLT_IPV6) {
      fprintf(stderr, "Unsupported link type: %d\n", link_type);
      return 2;
    }

    //Packet filtering keep only ARP
    if(pcap_compile(handle, &filter, filter_desc, 0, 0) == -1  || pcap_setfilter(handle, &filter)==-1){
      fprintf(stderr, "Bad filter - %s\n", pcap_geterr(handle));
      return 2;
    }

    loadARPTable();

    fOut = fopen (output_file_name,"w");
    fprintf(fOut, "packet_counter, mac_destination, mac_source, type, hardware type, protocol type, hardware size, protocol size,  opcode, mac_sender, ip_sender, mac_target, ip_target, error definition\n");


    packet_counter = 0;
    pcap_loop(handle, 0, my_packet_handler, NULL);
    pcap_close(handle);

    fclose(fOut);

    storeARPTable();

    return(0);
  }
