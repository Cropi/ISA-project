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

/* DNS hdr, TCP has another field called 'length'. */
/*struct dnshdr {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __attribute__((packed));*/

// ATTENTION!!!
// SOURCE: https://0x00sec.org/t/dns-header-for-c/618
struct dnshdr {
	uint16_t id;
# if __BYTE_ORDER == __BIG_ENDIAN
	uint16_t qr : 1;
	uint16_t opcode : 4;
	uint16_t aa : 1;
	uint16_t tc : 1;
	uint16_t rd : 1;
	uint16_t ra : 1;
	uint16_t zero : 3;
	uint16_t rcode : 4;
# elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t rd : 1;
	uint16_t tc : 1;
	uint16_t aa : 1;
	uint16_t opcode : 4;
	uint16_t qr : 1;
	uint16_t rcode : 4;
	uint16_t zero : 3;
	uint16_t ra : 1;
# else
#  error "Adjust your <bits/endian.h> defines"
# endif
	uint16_t qcount;	/* question count */
	uint16_t ancount;	/* Answer record count */
	uint16_t nscount;	/* Name Server (Autority Record) Count */
	uint16_t adcount;	/* Additional Record Count */
};


/* This functions is called from main.c . Parses pcap file */
void parsePcapFile(argument a);

bool isDNSRequired(int type);

/* Parses each field according to its type */
string parseDNSdata(u_char *act, unsigned int type, const u_char *rdata);

/* skip dns Questions/AnswerRRs/AuthorityRRs/AdditionalRRs */
u_char *jumpToDnsAnswers(u_char *label);

/* Interprets dns labels/pointers into human-readable text */
string dnsNameToString(u_char **label, const u_char *payload, const u_char *end);

/* Parses signature name and returns interpreted data */
string getSignatureName(u_char *act, int len);
string toHexa(u_char *n);

#endif
