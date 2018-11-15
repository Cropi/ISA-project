#ifndef ARG_PARSER_H
#define ARG_PARSER_H

#include <iostream>
#include <cstdbool>
#include <unistd.h>
#include <cstring>
#include <string>
#include <regex>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "constants.h"
using namespace std;

/* Structure to captrue input arguments */
struct argument {
    bool r = false;
    bool i = false;
    bool s = false;
    bool t = false;
    string file_name;
    string interface;
    string syslog;
    double seconds;
};

/* Check whether inpur arguments are correc */
int checkArguments(int argc, char **argv, argument *a);

/* Output erroMSG to stderr */
void errorMsg(returnCode r, char *message);

bool isArgument(char *string);

bool isNumber(const std::string& s);



#endif
