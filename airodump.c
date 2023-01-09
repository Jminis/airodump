#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

struct ieee80211_radiotap_header { //radiotap 헤더 구조체
    u_int8_t it_version;     /* set to 0 */
    u_int8_t it_pad;
    u_int16_t it_len;         /* entire length */
    u_int32_t it_present;     /* fields present */
} __attribute__((__packed__));


struct ieee80211_beacon_header{ //beacon 헤더 구조체 일부
	u_int32_t frame_field;
	u_int8_t destination_addr[6];
	u_int8_t source_addr[6];
	u_int8_t bss_id[6];
	u_int8_t dummy[14];
	u_int8_t tag_number;
	u_int8_t tag_length;
} __attribute__((__packed__));


struct ieee80211_temp_header{ //주요 정보 구조체
	u_int8_t bssid[6];
	int pwr;
	int beacons;
	u_int8_t tag_length;
	unsigned char essid[32];
	struct ieee80211_temp_header *next;
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

struct ieee80211_temp_header *main_header; //연결리스트 구조의 root node


bool save_beacon(struct ieee80211_temp_header *temp_header){ //beacon 헤더 저장 with 연결리스트 구조
	struct ieee80211_temp_header *curr = main_header;
	while(curr->next != NULL){
		if(memcmp(curr->bssid,temp_header->bssid,6)==0){
			curr->pwr = temp_header->pwr;
			curr->beacons++;
			return false;
		}
		curr = curr->next;
	}

	memcpy(curr ->bssid,temp_header->bssid,6);
	memcpy(curr ->essid,temp_header->essid,temp_header->tag_length);
	curr->tag_length = temp_header->tag_length;
	curr->pwr = temp_header->pwr;
	curr->beacons = 1;
	curr->next = malloc(sizeof(struct ieee80211_temp_header));
	curr->next->next = NULL;

	return true;
}

bool check_beacon(const u_char *packet){ //beacon 패킷인지 판별
	struct ieee80211_radiotap_header* radiotap_header;
	radiotap_header = (struct ieee80211_radiotap_header* )packet;

	if(*(packet+radiotap_header->it_len)==0x80) return true;
	else return false;

}

void print_info(){ //출력 함수
	struct ieee80211_temp_header *curr = main_header;

	system("clear");
	printf("=====================================================\n");
	printf("BSSID\t\t\tPWR   \tbeacons\t\tSSID\n");
	while(curr->next != NULL){
		for(int i=0;i<6;i++){
			printf("%02x",curr->bssid[i]);
			if(i!=5)
				printf(":");
		}
		printf(" \t%d\t%d\t\t%s\n",(curr->pwr)-0xff+0x1,curr->beacons,curr->essid);
		curr = curr->next;
	}

}

bool parse_info(const u_char *packet){ //주요 정보 파싱 함수
	struct ieee80211_beacon_header* beacon_header;
	struct ieee80211_temp_header* temp_header = malloc(sizeof(struct ieee80211_temp_header));

	if(!check_beacon(packet)) return false;
	beacon_header = (struct ieee80211_beacon_header *)(packet+24);

	memcpy(temp_header->bssid,beacon_header->bss_id,6); //BSSID parsing
	temp_header->pwr = *(packet+18); //PWR parsing
	memcpy(temp_header->essid,packet+24+38,beacon_header->tag_length); //ESSID parsing
	temp_header->tag_length = beacon_header->tag_length;
	save_beacon(temp_header);

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
	main_header = malloc(sizeof(struct ieee80211_temp_header));
	main_header->next = NULL;
	
	while (true) {
		
		struct pcap_pkthdr* header;
		const u_char* packet;

		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		parse_info(packet);
		print_info();
	}


	pcap_close(pcap);
}

