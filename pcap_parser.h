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
struct dnshdr {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __attribute__((packed));


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
