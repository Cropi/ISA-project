#ifndef SYSLOG_H
#define SYSLOG_H

#include "constants.h"
#include "arg_parser.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctime>
#include <netdb.h>
#include <list>
#include <iostream>
using namespace std;

#define SYSLOG_MSGLEN 512
/* Facility indicates message priority */
enum Facility {
    F_KERNEL_MESSAGE = 0,           // kernel messages
    F_USER_LEVEL_MESSAGE = 1,       // user-level messages
    F_MAIL_SYSTEM = 2,              // mail system
    F_SYSTEM_DAEMOUNS = 3,          // system daemons
    F_SECURITY_MESSAGES = 4,        // security/authorization messages
    F_MESSAGE_INTERNALLY = 5,       // messages generated internally by syslogd
    F_LINE_POINTER = 6,             // line printer subsystem
    F_NETWORK_NEWS_SUBSYSTEM = 7,   // network news subsystem
    F_UUCP_SUBSYSTEM = 8,           // UUCP subsystem
    F_CLOCL_DAEMON = 9,             // clock daemon
    F_SECURITY_AUTH_MESSAGE = 10,   // security/authorization messages
    F_FTP_DAMON = 11,               // FTP daemon
    F_NTP_SUBSYTEM = 12,            // NTP subsystem
    F_LOG_AUDIT = 13,               // log audit
    F_LOG_ALERT = 14,               // log alert
    F_CLOCK_DAMON = 15,             // clock daemon (note 2)
    F_LOCAL_USE0 = 16,              // local use 0  (local0)
    F_LOCAL_USE1 = 17,              // local use 1  (local1)
    F_LOCAL_USE2 = 18,              // local use 2  (local2)
    F_LOCAL_USE3 = 19,              // local use 3  (local3)
    F_LOCAL_USE4 = 20,              // local use 4  (local4)
    F_LOCAL_USE5 = 21,              // local use 5  (local5)
    F_LOCAL_USE6 = 22,              // local use 6  (local6)
    F_LOCAL_USE7 = 23,              // local use 7  (local7)
};

/* Severity indicates message priority */
enum Severity {
    S_EMERGENCY = 0,    // Emergency: system is unusable
    S_ALERT = 1,        // Alert: action must be taken immediately
    S_CRITICAL = 2,     // Critical: critical conditions
    S_ERROR = 3,        // Error: error conditions
    S_WARNING = 4,      // Warning: warning conditions
    S_NOTICE = 5,       // Notice: normal but significant condition
    S_INFORMATIONAL = 6,// Informational: informational messages
    S_DEBUG = 7,        // Debug: debug-level messages
};

/* This functions is called from main.c */
int syslogServer(string syslog_server);

/* Creates syslog message header + content */
void createSyslogMessages(map<string, int> &messages, list<string> &answers, Facility f, Severity s, int v, string app_name);
string createSyslogMessageHeader(Facility f, Severity s, int v, string app_name);
string createSyslogMessageHeaderPriority(Facility f, Severity s);
string createSyslogMessageHeaderVersion(int version);
string createSyslogMessageHeaderTime();
string createSyslogMessageHeaderHostname();
string createSyslogMessageHeaderApp(string app_name);

/* sends messages to syslog server */
int sendSyslogMessages(int source, list<string> &answers);

/* Creates connection with syslog server */
int connectToSyslog(const char *syslog_server, const char *port, struct addrinfo *hints, struct addrinfo **result);

#endif
