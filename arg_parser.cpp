#include "arg_parser.h"


void errorMsg(returnCode r, char *message){
    cerr << "Error:\t" << message;
    cerr << "\tFor more informations run ./dns-export -h\n";
    exit(r);
}

int checkArguments(int argc, char **argv, argument *a) {
    if (argc == 1) {
        cerr << "Without arguments this program has no funcionality.\nExecute with -h parameter to get additional informations.\n";
        exit(R_OKAY);
    }
    else if (argc == 2) {
        if (strcmp(argv[1], "-h") == 0) {
            cout <<
            "dns-export [-r file.pcap] [-i interface] [-s syslog-server] [-t seconds]\n"
            "\t-r file.pcap Must be a valid .pcaf file\n"
            "\t-i interface Listens to the requested interface\n"
            "\t-s hostname/ipv4/ipv6 adress for the syslog server\n"
            "\t-t Time for computing statistics, default value is 60 seconds\n";
            exit(R_OKAY);
        }
    }

    int opt;
    string s;

    while ((opt = getopt(argc, argv, "r:i:s:t")) != EOF) {
        switch (opt) {
            case 'r':
                if (a->r) errorMsg(R_DUPLICIT_PARAM, (char *)".pcap file was specified before.\n");
                a->r = true;
                a->file_name = optarg;
                // a->file_name = "asd";
                break;
            case 'i':
                if (a->i) errorMsg(R_DUPLICIT_PARAM, (char *)"Interface was specified before.\n");
                a->i = true;
                a->interface = optarg;
                break;

            case 's':
                if (a->s) errorMsg(R_DUPLICIT_PARAM, (char *)"Syslog-server was specified before.\n");
                a->s = true;
                a->syslog = optarg;
                break;

            case 't':
                if (a->t) errorMsg(R_DUPLICIT_PARAM, (char *)"Time was specified before.\n");
                a->t = true;
                if (argv[optind] != nullptr) {
                    if (isArgument(argv[optind])) {
                        a->seconds = 60;
                    }
                    else {
                        s = argv[optind];
                        if (regex_match(s, regex("^(\\+)?(0|([1-9][0-9]*))(\\.[0-9]+)?$"))) {
                            a->seconds = atof(s.c_str());
                        }
                        else {
                            errorMsg(R_INVALID_TIME, (char *)"-t optarg must be a valid unsigned double\n");
                        }
                    }
                }
                else {
                    a->seconds = 60;
                }
                break;

            default:
                errorMsg(R_UNKNOWN_PARAM, (char *)"Unknown argument or argument without required optarg detected.\n");
                break;
        }

        if (a->r && a->i)
            errorMsg(R_INVALID_COMBINATION, (char *)"Patameters: pcaf file[-r] and interace[-i] can not be combined\n");
        else if (a->r && a->t)
            errorMsg(R_INVALID_COMBINATION, (char *)"Parameters: pcaf file[-r] and time[-t] can not be combined\n");
    }

    return R_OKAY;
}

bool isArgument(char *string) {
    const char *array[] = {"-r", "-i", "-s"};
    for(int i = 0; i < 3; i++) {
        if (strcmp(array[i], string)==0)
            return true;
    }
    return false;
}
