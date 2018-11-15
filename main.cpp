/*
 * Project:     ISA
 * Date:        30.10.2018
 * Author:      Attila Lakatos
 * Login:       xlakat01
 * Email:       xlakat01@stud.fit.vutbr.cz
 * Hours spent on this project: too many... :D
 */

#include <iostream>
#include <cstring>
#include <signal.h>
#include <unistd.h>
#include <list>

#include "constants.h"
#include "arg_parser.h"
#include "pcap_parser.h"
#include "interface.h"
#include "syslogmessage.h"

using namespace std;
void signalHandler(int signum); /* reacts to SYGUSR1 signal */
void sendToSyslog(int signum); /* after a period of time sends packets to syslog server */
void printOutStatistics();
list<string> results; /* each dns packet is saved in a list */
unsigned int seconds; /* period of time after statistics are sent */
string syslog_server; /* syslog server name */
bool s = false; /* indicates if syslog server is defined */
string app_name; /* application name: dns-export */

/* Filter port 53 for dns capture */
const char *filter =
	// " ((tcp[10] & 0x80 = 128) or "
	// " (udp[10] & 0x80 = 128)) and "
	// " port 53"
	// ;
	// "port 53 and ("
	// "(udp and (not udp[10] & 128 = 0)) or"
	// "(tcp and (not tcp[((tcp[12] & 0xf0) >> 2) + 2] & 128 = 0))"
	// ")";
	"port 53";

/* support DNS types */
std::map<int, string> RRtypes = {
    make_pair(RR_A, "A"),			// OK
	make_pair(RR_NS, "NS"),			// OK
	make_pair(RR_CNAME, "CNAME"),	// OK
	make_pair(RR_SOA, "SOA"),		// OK
	make_pair(RR_PTR, "PTR"),		// OK - DOES NOT NEED BUT IMPLEMENTED
	make_pair(RR_MX, "MX"),			// OK
	make_pair(RR_TXT, "TXT"),		// OK
    make_pair(RR_AAAA, "AAAA"),		// OK
	make_pair(RR_DS, "DS"),			// OK
	make_pair(RR_RRSIG, "RRSIG"),	// OK
	make_pair(RR_NSEC, "NSEC"),		// OK
	make_pair(RR_DNSKEY, "DNSKEY"),	// OK
	make_pair(RR_SPF, "SPF"),		// elvileg OK
};



int main(int argc, char **argv)
{
    signal(SIGUSR1, signalHandler);
	signal(SIGALRM, sendToSyslog);

    argument a;
	app_name = argv[0];
    checkArguments(argc, argv, &a);

	if (a.s) { /* syslog server */
		s = true;
		syslog_server = a.syslog;
	}

    if (a.r) { /* Parse pcap file */
        parsePcapFile(a);
		printOutStatistics();
    }
    else if (a.i) { /* sniff interface */
		seconds = a.seconds;
		alarm(seconds);
        listenToInterface(a);
    }

    exit(R_OKAY);
}

void signalHandler(int signum)
{
    if (signum == SIGUSR1) {
        cout << "LOG: Received SIGUSR1! Printing out statistics\n" ;
		printOutStatistics();
    }
}

void printOutStatistics() {
	map<string, int> tmp;
	for (list<string>::iterator it = results.begin(); it != results.end(); ++it){
		tmp[*it] += 1;
	}

	for (auto it = tmp.begin(); it != tmp.end(); ++it){
		cout << it->first << it->second << "\n";
	}
}

void sendToSyslog(int signum) {
	cout << "LOG: Sending to syslog\n";
	if (s)
		syslogServer(syslog_server);
	alarm(seconds);
}
