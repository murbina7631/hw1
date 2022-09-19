#define APP_NAME		"sniff and spoof"
#define APP_DESC		"Sniffer then spoof using libpcap"

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* don't fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

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

/* ADDED HEADER AND CHECKSUM FUNCTION FOR SPOOFING HERE */
struct ipheader {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* don't fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

struct icmpheader {
		u_char  icmp_type;           /* message type */
		u_char  icmp_code;           /* error code */
		u_short icmp_sum;            /* checksum */
		u_short icmp_id;             /* identification */
		u_short icmp_seq;            /* sequence number */
};

u_short calc_checksum(u_short *buffer, int len) {
	int nleft = len;
	int sum = 0;
	u_short *w = buffer;
	u_short temp = 0;

	// Convert character from w to hex and add to checksum.
	// Iterate through w until no more characters left.
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	// In these of a byte being left over, add to checksum.
	if (nleft == 1) {
		*(u_char *) (&temp) = *(u_char *) w;
		sum += temp;
	}
	
	// Discard any carry.
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	return (~sum);
}

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_app_banner(void);

void
print_app_usage(void);

/*
 * app name/banner
 */
void
print_app_banner(void)
{

	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("\n");

return;
}

/*
 * print help text
 */
void
print_app_usage(void)
{

	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

return;
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */

	int size_ip;

	printf("\nPacket number %d:\n", count);
	count++;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));

	/* determine protocol */
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			return;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			
			/* ADDED SPOOFING CODE HERE */
			// This buffer will be used to construct the raw packet.
			char buffer[1024];
			
			// Typecasting the buffer to the IP header structure.
			struct ipheader *ip_send = (struct ipheader *) buffer;
			
			// Typecasting the buffer to the ICMP header structure.
			struct icmpheader *icmp = (struct icmpheader *) (buffer + sizeof(struct ipheader));

			// Assign value to the IP and ICMP header fields.
			ip_send->ip_vhl = 0x45;					// Protocol IPv4 : Header Length
			ip_send->ip_tos = 0x0;
			// Note: htons required
			ip_send->ip_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));
			ip_send->ip_id = 0x0;					// Uniquely identifies each datagram sent
			ip_send->ip_off = 0x0;					// Fragment offset
			ip_send->ip_ttl = 20;					// Maximum number of hops packet can take
			ip_send->ip_p = IPPROTO_ICMP;
			ip_send->ip_sum = 0x0;					// Checksum field
			ip_send->ip_src = ip->ip_dst;
			ip_send->ip_dst = ip->ip_src;

			icmp->icmp_type = 8;			// ICMP_ECHO = 8
			icmp->icmp_code = 0x0;
			icmp->icmp_sum = 0x0;
			icmp->icmp_id = htons(8888);
			icmp->icmp_seq = htons(0x0);
			
			icmp->icmp_sum = calc_checksum((unsigned short *) icmp, sizeof(struct icmpheader));
			ip_send->ip_sum = calc_checksum((unsigned short *) ip_send, sizeof(struct ipheader));
			
			// Send the spoofed packet
			int sd;
			struct sockaddr_in sin;
			//char buffer[1024]; // You can change the buffer size

			/* Create a raw socket with IP protocol. The IPPROTO_RAW parameter
			CSCE 465 Computer and Network Security 3
			* tells the sytem that the IP header is already included;
			* this prevents the OS from adding another IP header. */
			sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
			if(sd < 0) {
				perror("socket() error"); exit(-1);
			}

			/* This data structure is needed when sending the packets
			* using sockets. Normally, we need to fill out several
			* fields, but for raw sockets, we only need to fill out
			* this one field */
			sin.sin_family = AF_INET;

			// Here you can construct the IP packet using buffer[]
			// - construct the IP header ...
			// - construct the TCP/UDP/ICMP header ...
			// - fill in the data part if needed ...
			// Note: you should pay attention to the network/host byte order.
			/* Send out the IP packet.
			* ip_len is the actual size of the packet. */
			if(sendto(sd, buffer, ntohs(ip_send->ip_len), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
				perror("sendto() error"); exit(-1);
			}
			
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}
}

int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "icmp[icmptype] == 8";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	//int num_packets = 10;			/* number of packets to capture */

	print_app_banner();

	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		print_app_usage();
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	//printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, -1, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}
