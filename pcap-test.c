#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

// IPv6 헤더 구조체 정의
struct libnet_ipv6_hdr
{
    u_int8_t ip_flags;     /* version, traffic class, flow label */
    u_int16_t ip_len;         /* total length */
    u_int8_t ip_nh;           /* next header */
    u_int8_t ip_hl;           /* hop limit */
    struct libnet_in6_addr ip_src;
    struct libnet_in6_addr ip_dst; /* source and dest address */

};
struct libnet_ipv6_frag_hdr
{
    u_int8_t ip_nh;          /* next header */
    u_int8_t ip_reserved;    /* reserved */
    u_int16_t ip_frag;       /* fragmentation stuff */
    u_int32_t ip_id;         /* id */
};
struct libnet_ipv6_routing_hdr
{
    u_int8_t ip_nh;          /* next header */
    u_int8_t ip_len;         /* length of header in 8 octet units (sans 1st) */
    u_int8_t ip_rtype;       /* routing type */
    u_int8_t ip_segments;    /* segments left */
    /* routing information allocated dynamically */
};
struct libnet_ipv6_destopts_hdr
{
    u_int8_t ip_nh;          /* next header */
    u_int8_t ip_len;         /* length of header in 8 octet units (sans 1st) */
    /* destination options information allocated dynamically */
};
struct libnet_ipv6_hbhopts_hdr
{
    u_int8_t ip_nh;          /* next header */
    u_int8_t ip_len;         /* length of header in 8 octet units (sans 1st) */
    /* destination options information allocated dynamically */
};


//TCP 세그먼트 소스주소 & 목적지 주소 
struct tcp_hdr {
	u_int8_t src_port; //src port 16비트
	u_int8_t dst_port; // dst port 16비트
	u_int8_t seq_num; //시퀀스 번호 [32]
	u_int8_t ACK_num;//승인번호[32]
	int data_offset;
	int reserved;
	u_int8_t flag;
	u_int8_t win;
	u_int8_t checksum;
	u_int8_t urgent;
	
}




void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test dum0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	printf("It's work!");
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
	}

	pcap_close(pcap);
}
