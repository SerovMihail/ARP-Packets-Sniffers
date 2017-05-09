#ifndef PACKET_STRUCT_H_INCLUDED
#define PACKET_STRUCT_H_INCLUDED

#include <sys/types.h>
#define BUFF_SIZE 1518
#define ETH_SIZE 14
#define ARP_SIZE 28
/* in bytes */
#define ETH_ADDR_SIZE 6
#define IP_ADDR_SIZE 4

typedef struct pkt_eth
{
    unsigned char dest[ETH_ADDR_SIZE];
    unsigned char src[ETH_ADDR_SIZE];
    unsigned short type;
} pkt_eth;

#define ETHERTYPE_ARP 0x0806
#define ARP_REQUEST 1
#define ARP_REPLY 2
typedef struct pkt_arp
{
    unsigned short htype;/* hardware type => ethernet , etc */
    unsigned short ptype; /*protocol type => ipv4 or ipv6 */
    unsigned char hard_addr_len; /* usually 6 bytes for ethernet */
    unsigned char proto_addr_len; /*usually 8 bytes for ipv4 */
    unsigned short opcode; /* type of arp */
    unsigned char hard_addr_send[ETH_ADDR_SIZE];
    unsigned char proto_addr_send[IP_ADDR_SIZE];
    unsigned char hard_addr_dest[ETH_ADDR_SIZE];
    unsigned char proto_addr_dest[IP_ADDR_SIZE];
} pkt_arp;

#define ETHERTYPE_IP 0x0800
typedef struct pkt_ip
{
    unsigned char vhl;
    unsigned char tos;
    unsigned short len;
    unsigned short id;
    unsigned short off;
    unsigned char ttl;
    unsigned char proto;
    unsigned short crc;
    unsigned int addr_src;
    unsigned int addr_dest;
} pkt_ip;

#endif // PACKET_STRUCT_H_INCLUDED
