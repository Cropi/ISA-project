#ifndef ARG_PARSER_H
#define ARG_PARSER_H

#include <iostream>
#include <cstdbool>
#include <unistd.h>
#include <cstring>
#include <string>
#include <regex>
#include "constants.h"
using namespace std;


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

int checkArguments(int argc, char **argv, argument *a);
void errorMsg(returnCode r, char *message);
bool isArgument(char *string);



#endif
