#include "syslogmessage.h"

extern list<string> results;
extern string app_name;

int syslogServer(string syslog_server) {
    list<string> tmp = results, answers;
    map<string, int> messages;
    struct addrinfo hints;
    struct addrinfo *result;
    int sfd, v;
    Facility f;
    Severity s;

    for (list<string>::iterator it = tmp.begin(); it != tmp.end(); ++it){
        messages[*it] += 1;
    }
	if (messages.size() == 0)
		return 0;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
    hints.ai_flags = 0;
    hints.ai_protocol = IPPROTO_UDP;          /* UDP protocol */

    sfd = connectToSyslog(syslog_server.c_str(), "514", &hints, &result);

    f = F_LOCAL_USE0;
    s = S_INFORMATIONAL;
    v = 1;

    createSyslogMessages(messages, answers, f, s, v, app_name);

    sendSyslogMessages(sfd, answers);
}

int connectToSyslog(const char *syslog_server, const char *port, struct addrinfo *hints, struct addrinfo **result) {
    struct addrinfo *rp;
    int sfd, s;
    s = getaddrinfo(syslog_server, "514", hints, result);
    if (s != 0) {
        errorMsg(R_SYSLOG_ERROR, (char *)"Could not find hostname/IPv4/IPv6\n");
        exit(EXIT_FAILURE);
    }

    for (rp = *result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1)
            continue;

        if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
            break;                  /* Success */

        close(sfd);
    }

    if (rp == NULL) {               /* No address succeeded */
        errorMsg(R_SYSLOG_ERROR, (char *)"Could not estabilish connections");
    }

    freeaddrinfo(*result);           /* No longer needed */

    return sfd;
}

int sendSyslogMessages(int source, list<string> &answers) {
    for (list<string>::iterator it = answers.begin(); it != answers.end(); ++it){
        if(send(source, it->c_str(), it->size(), 0) == -1) {
            errorMsg(R_SYSLOG_ERROR, (char *)"Error while sending packets\n");
        }
    }
}

void createSyslogMessages(map<string, int> &messages, list<string> &answers, Facility f, Severity s, int v, string app_name) {
    string msg;
    char data[128];
    for (auto it = messages.begin(); it != messages.end(); ++it){
        string sys_hdr = createSyslogMessageHeader(f, s, v, app_name);

        snprintf(data, 128, "%d", it->second);
        msg =  sys_hdr + it->first + ' ' + data;

        answers.push_back(msg);
    }
}

string createSyslogMessageHeader(Facility f, Severity s, int v, string app_name) {
    return  createSyslogMessageHeaderPriority(f, s)   +
            createSyslogMessageHeaderVersion(v) + ' ' +
            createSyslogMessageHeaderTime() + ' '     +
            createSyslogMessageHeaderHostname() + ' ' +
            createSyslogMessageHeaderApp(app_name) + " --- ";
}

string createSyslogMessageHeaderPriority(Facility f, Severity s) {
    int priority = f * 8 + s;
    char data[128];
    snprintf(data, 128, "<%d>", priority);
    return data;
}
string createSyslogMessageHeaderVersion(int version) {
    char data[128];
    snprintf(data, 128, "%d", version);
    return data;
}

string createSyslogMessageHeaderTime() {
    char data[256];
    time_t DateTime;
    time(&DateTime);
    tm *DateTimeStruct;
    DateTimeStruct =  gmtime(&DateTime);
    timeval curTime;
    gettimeofday(&curTime, NULL);
    int milli = curTime.tv_usec / 1000;

    snprintf(data, 256, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", DateTimeStruct->tm_year+1900, DateTimeStruct->tm_mon+1, DateTimeStruct->tm_mday, DateTimeStruct->tm_hour+1, DateTimeStruct->tm_min, DateTimeStruct->tm_sec, (1000-milli));

    return data;
}

string createSyslogMessageHeaderHostname() {
    char data[128];
    int hostname = gethostname(data, 128);
    if (hostname == 0)
        return data;
    else
        return "NULL";
}

string createSyslogMessageHeaderApp(string app_name) {
    if (app_name.substr(0, 2) == "./")
        return app_name.substr(2);
    return app_name;
}
