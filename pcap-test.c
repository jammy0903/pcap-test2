#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

struct ether_header *eth_hdr;
struct tcphdr *tcp_hdr;
struct ip *ip_hdr;


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
        int res = pcap_next_ex(pcap, &header, &packet); // pck_hdr's ptr's ptr=>header's wichi  && packet pointer
        //'header' include metadata.
        //'packet' include packet data
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);

        /*  이더넷 패킷헤더 포인터 가리키기
                    이더넷 길이는 정해져있으므로 구할 필요 x
                    이더넷 mac 주소 구하기 (src, dst)
                    IP헤더 위치 구하기 packet + sizeof(struct ether_header)
                    IP헤더 길이 구하기 ip_hl 를 구하고 바이트로 변환해야함.
                    IP src,dst 구하기
                    TCP헤더 위치 구하기(ip길이로)
                    tcp 인지아닌지 판별
                    tcp이면 -> src port / dst port 출력
                    else-> continue (?문법 맞는지 확인헤야함)
                    payload  hexadecimal value for문돌려서 10까지만 출력

                */

           eth_hdr= (struct ether_header*)packet; //pkt chg into header's ptr
           ip_hdr = (struct ip*)(packet + sizeof(struct ether_header));
          //u_int8_t ip_p= ip_hdr->ip_hl*4; //ip's length must be byte!!
           tcp_hdr= (struct tcphdr*)(packet +sizeof(struct ip));

           if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) continue;
             printf("type = %04x \n", ntohs(eth_hdr->ether_type));

           if (ip_hdr->ip_p != IPPROTO_TCP) continue;
             printf("proto = %d \n", ip_hdr->ip_p);

	}

	pcap_close(pcap);
}
