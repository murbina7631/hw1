#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

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
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

struct udpheader {
		u_int16_t udp_src_port;           /* source port */
		u_int16_t udp_dst_port;           /* destination port */
		u_int16_t udp_ulen;            	  /* udp length */
		u_int16_t udp_sum;             	  /* udp checksum */
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

int main() {
	// This buffer will be used to construct the raw packet.
	char buffer[1024];
	
	// Typecasting the buffer to the IP header structure.
	struct ipheader *ip = (struct ipheader *) buffer;
	
	// Typecasting the buffer to the UDP header structure.
	struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));

	// Assigning the buffer with a payload.
	char *data = buffer + sizeof(struct ipheader) + sizeof(struct udpheader);
	int data_len = 11;
	strncpy(data, "Hello world", data_len);

	// Assign value to the IP and UDP header fields.
	ip->ip_vhl = 0x45;						// Protocol IPv4 : Header Length
	ip->ip_tos = 0x0;
	// Note: htons required
	ip->ip_len = htons(sizeof(struct ipheader) + sizeof(struct udpheader) + data_len);
	ip->ip_id = 0x0;						// Uniquely identifies each datagram sent
	ip->ip_off = 0x0;						// Fragment offset
	ip->ip_ttl = 20;						// Maximum number of hops packet can take
	ip->ip_p = IPPROTO_UDP;
	ip->ip_sum = 0x0;						// Checksum field
	ip->ip_src.s_addr = inet_addr("10.0.1.188");
	ip->ip_dst.s_addr = inet_addr("10.0.1.112");

	udp->udp_src_port = htons(7777);
	udp->udp_dst_port = htons(9999);
	udp->udp_ulen = htons(sizeof(struct udpheader) + data_len);
	udp->udp_sum = 0x0;						// Checksum field
	
	udp->udp_sum = calc_checksum((unsigned short *) udp, sizeof(struct udpheader));
	ip->ip_sum = calc_checksum((unsigned short *) ip, sizeof(struct ipheader));
	
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
	if(sendto(sd, buffer, ntohs(ip->ip_len), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("sendto() error"); exit(-1);
	}

	return 0;

}