#ifndef PCAP_PARSER_H
#define PCAP_PARSER_H

#include "arg_parser.h"

#include <list>
#include <map>
#include <iostream>
#include <stdbool.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

using namespace std;

#define SIZE_ETHERNET (14)

struct dnshdr {
	// union {
	// 	uint16_t len;
	// };

	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __attribute__((packed));


bool isDNSRequired(int type);
void parsePcapFile(argument a);
string parseDNSdata(u_char *act, unsigned int type, const u_char *rdata);
u_char *jumpToDnsAnswers(u_char *label);
string dnsNameToString(u_char **label, const u_char *payload, const u_char *end);
string getSignatureName(u_char *act, int len);
string toHexa(u_char *n);

#endif
