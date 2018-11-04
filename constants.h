#ifndef CONSTANTS_H
#define CONSTANTS_H

enum returnCode {
    R_OKAY = 1,
    R_UNKNOWN_PARAM,
    R_INVALID_COMBINATION,
    R_DUPLICIT_PARAM,
    R_INVALID_TIME,
    R_PCAP_INVALID_FILE,
    R_PCAP_PARSE_ERROR,
    R_DEVICE_ERROR,
    R_LOOKUPNET_FAIL,
    R_INVALID_SYSLOG,
    R_SYSLOG_ERROR,
};

enum resourceRecourdTypes {
	RR_A     = 1,
	RR_NS    = 2,
	RR_CNAME = 5,
	RR_SOA   = 6,
	RR_PTR   = 12,
	RR_MX    = 15,
	RR_TXT   = 16,
	RR_AAAA  = 28,
	RR_DS    = 43,
	RR_RRSIG = 46,
	RR_NSEC  = 47,
	RR_DNSKEY= 48,
	RR_SPF   = 99,
};

#define PCAP_BUFFER_SIZE 4096

#endif
