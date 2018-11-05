#ifndef INTERACE_H
#define INTERACE_H

#include "constants.h"
#include "arg_parser.h"
#include "pcap_parser.h"

#include <string>
#include <unistd.h>
#include <signal.h>
using namespace std;

/* Sniff interace */
void listenToInterface(argument a);

#endif
