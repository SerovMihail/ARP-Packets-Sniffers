#include<stdio.h>
#include<stdlib.h>
#include<netinet/in.h> // for addresses translation
#include<errno.h>
// for ntohs etc
// can also be necessary to include netinet/in
#include <arpa/inet.h>

#include "packet_struct.h"
#include "packet_print.c"

#include <pcap.h>
#include <netinet/ether.h>


#define SNAP_LEN 1518
int packet_count = 0;
void handleARP(const struct pkt_eth * eth)
{

    struct pkt_arp * arp = (/*const*/ struct pkt_arp *) (eth + 1);

    print_pkt_arp(arp);
    if(ntohs(arp->htype) != 1)
    {
        fprintf(stderr, "Error : ARP packet does not contain a Hardware type Ethernet -> %d\n",ntohs(arp->htype));
        return;
    }

    // check protocol type
    if(ntohs(arp->ptype) != 0x800)
    {
        fprintf(stderr,"Error : ARP packet does not contain a IPv4 type\n");
        return;
    }

}

void sniff_callback(u_char * user, const struct  pcap_pkthdr * h,const u_char * bytes)
{
    int i = 0;
    for(i=0; i < 25; i++)
    {
        printf("-");
    };
    printf("\n");
    printf("Received packet number %d ==> %d\n",packet_count++,h->len);
    const struct pkt_eth * eth;
    unsigned short eth_type;

    unsigned int captureLength = h->caplen;
    unsigned int packetLength = h->len;

    if(captureLength != packetLength)
    {
        fprintf(stderr,"Error : received packet with %d available instead of %d \n",captureLength,packetLength);
        return;
    }
    if(captureLength < ETH_SIZE)
    {
        fprintf(stderr,"Error : received too small packet , %d bytes",captureLength);
        return;
    }

    eth = (struct pkt_eth*)(bytes);

    // print the packet
    print_pkt_eth(eth);

    eth_type = ntohs(eth->type);

    if(eth_type == ETHERTYPE_ARP)
    {
        handleARP(eth);
    }

    for(i=0; i < 25; i++)
    {
        printf("-");
    };
    printf("\n");
    return;

}

/* returns 0 if everything went well */
int set_options(pcap_t * handle)
{
    int ret = 0;

    ret = pcap_set_promisc(handle,1);
    if(ret != 0)
    {
        fprintf(stderr,"Error setting promiscuous mode\n");
        return ret;
    }
    ret = pcap_set_snaplen(handle,SNAP_LEN);
    if(ret != 0)
    {
        fprintf(stderr,"Error setting snapshot length\n");
        return ret;
    }
    ret = pcap_set_timeout(handle,1000);
    if(ret != 0)
    {
        fprintf(stderr,"Error setting timeout\n");
        return ret;
    }

    return ret;
}
int activate(pcap_t * handle)
{
    int ret = pcap_activate(handle);
    switch(ret)
    {
    case 0:
        fprintf(stdout,"Activation complete\n");
        break;
    case PCAP_WARNING_PROMISC_NOTSUP:
        fprintf(stderr,"Promiscuous mode not supported\n");
        return ret;
    case PCAP_ERROR_PERM_DENIED:
        fprintf(stderr,"Not have the permission required\n");
        return ret;
    case PCAP_ERROR_PROMISC_PERM_DENIED:
        fprintf(stderr,"Not have the permission required for promiscuous\n");
        return ret;
    default:
        fprintf(stderr,"Error occured during activation, see code\n");
        return ret;
    }
    return ret;
}


/* Will activate device , filter & call the sniffing loop */
int sniffing_method(char * interface, char * filter,int packet_count)
{

    char err[PCAP_ERRBUF_SIZE]; //error buffer
    pcap_t * handle; // handler of the interface by pcap

    struct bpf_program bpf;
    bpf_u_int32 mask; // network mask
    bpf_u_int32 ip; // network ip
    struct in_addr addr; // network number

    int ret;

    /* get mask & ip */
    if(pcap_lookupnet(interface, &ip, &mask, err) == -1)
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",interface,err);
        exit(EXIT_FAILURE);
    }

    handle = pcap_create(interface,err);
    if (handle == NULL)
    {
        fprintf(stderr,"Error pcap_create() : %s \n",err);
        exit(EXIT_FAILURE);
    }
    if(set_options(handle) != 0)
    {
        fprintf(stderr,"Exiting\n");
        exit(EXIT_FAILURE);
    }
    if (activate(handle) != 0)
    {
        fprintf(stderr,"Exiting\n");
        exit(EXIT_FAILURE);
    }

    /* FILTER PART */
    if(filter != NULL)
    {
        if(pcap_compile(handle,&bpf,filter,0,ip) == -1)
        {
            fprintf(stderr,"Couldn't compile filter expr %s : %s\n",filter,pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }
        if(pcap_setfilter(handle, &bpf) == -1)
        {
            fprintf(stderr,"Couldn't install filter %s : %s\n",filter,pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }
    }

    /* SNIFF starts */
    printf("Sniffing starting on %s ...\n",interface);
    pcap_loop(handle,packet_count,sniff_callback,NULL);

    pcap_freecode(&bpf);
    pcap_close(handle);

    return EXIT_SUCCESS;
}
void usage()
{
    printf("sniff interface [filter] [count]");
    printf("interface is the interface you want to listen on. It will try to put it in monitor mode");
    printf("filter can be a filter for libpcap to apply for packets it reads");
}
int main(int argc, char * argv[])
{


    int i = 0; // counter
    int ret;
    char * default_filter = "ip";
    char * filter;

    int pcount = -1; //take all packet by defaults

    char * interface;
    if(argc < 2)
    {
        fprintf(stderr, "No interfaces specified in arguments\n");
        usage();
        exit(EXIT_FAILURE);
    }
    // take command line filter
    if(argc > 2)
    {
        filter = argv[2];
    }
    else
    {
        filter = default_filter;
    }
    // take command line packet count limit
    if(argc > 3)
    {
        pcount = atoi(argv[3]);
    }

    fprintf(stdout,"Args : ");
    for(i = 0; i < argc; i++)
    {
        fprintf(stdout,"\t%s",argv[i]);
    }
    printf("\n");

    interface = argv[1];

    sniffing_method(interface,filter,pcount);


    return 0;
}
