#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include "packet_struct.h"
#include "packet_print.h"
#include <time.h>

char* to_addr(unsigned char * addr, int length)
{
    int i = 0;
    char string[length];
    for(i=0; i< length; i++)
        sprintf(string,"%02x:",addr[i]);
    return string;
}

void print_pkt_eth(const struct pkt_eth * eth)
{
    int i = 0;

    fprintf(stdout,"Ethernet Layer \n");
    fprintf(stdout,"\tSource:\t");
    for(i=0; i<ETH_ADDR_SIZE; i++)
        fprintf(stdout,"%02x:",eth->src[i]);
    //fprintf(stdout,"%s",to_addr(eth->src,ETH_ADDR_SIZE));
    fprintf(stdout,"\n\tDest:\t");
    for(i=0; i<ETH_ADDR_SIZE; i++)
        fprintf(stdout,"%02X:",eth->dest[i]);

    if(ntohs(eth->type) == ETHERTYPE_IP)
        fprintf(stdout,"\n\tType:\t IPv4");
    else if(ntohs(eth->type) == ETHERTYPE_ARP)
        fprintf(stdout,"\n\tType:\t ARP");
    printf("\n");
}

void print_pkt_arp(pkt_arp * arp)
{
    int op = 0;
    int i = 0;

    time_t seconds;

    printf("ARP Layer \n");
    printf("\tHardware type:\t%02d\n",arp->htype);
    printf("\tProtocol type:\t%02d\n",arp->ptype);
    printf("\tHardware addresses length:\t%01d\n",arp->hard_addr_len);
    printf("\tProtocol addresses length:\t%01d\n",arp->proto_addr_len);
    op = ntohs(arp->opcode);
    printf("\tOperation code:\t%01u\n",op);
    printf("\tHardware sender:\t");
    for(i=0; i<ETH_ADDR_SIZE; i++)
        printf("%02x:",arp->hard_addr_send);
    printf("\n\tSoftware sender:\t");

    for(i=0; i<IP_ADDR_SIZE; i++)
        printf("%02x:",arp->proto_addr_send);

    seconds = time (NULL);
    printf("\nNow is time: %i ", seconds);
    printf("\n");

}

void print_pkt_ip(pkt_ip * ip)
{
}
