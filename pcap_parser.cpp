#include "pcap_parser.h"

extern list<string> results;
extern const char *filter;
extern map<int, string> RRtypes;

// #define DEBUGING 1

void parsePcapFile(argument a) {
    char err_buff[PCAP_BUFFER_SIZE];
    pcap_t *pcap_handler;
    const u_char *packet;
    struct pcap_pkthdr header;
    struct ether_header *eptr;
    struct ip *my_ip;
	unsigned counter = 1;
	struct bpf_program fp;
    map<long,long> tcpnum;


    if ((pcap_handler = pcap_open_offline(a.file_name.c_str(), err_buff)) == NULL) {
        string s = err_buff; s.append("\n");
        errorMsg(R_PCAP_INVALID_FILE, (char *)s.c_str());
    }

	if (pcap_compile(pcap_handler, &fp, filter, 0, 0) == -1) {
	    fprintf(stderr, "Couldn't parse filter %s: %s\n",
	        filter, pcap_geterr(pcap_handler));
	    exit(EXIT_FAILURE);
	}

	if (pcap_setfilter(pcap_handler, &fp) == -1) {
	    fprintf(stderr, "Couldn't install filter %s: %s\n",
	        filter, pcap_geterr(pcap_handler));
	    exit(EXIT_FAILURE);
	}

    while ((packet = pcap_next(pcap_handler, &header)) != NULL){
		const u_char *data = packet, *end;
		u_char *tmp;
		string answer_data;
		uint16_t qtype = 0;
		size_t payload_offset;
		int ip_protocol;

		switch (pcap_datalink(pcap_handler)) {
			case DLT_EN10MB:
				data += ETH_HLEN;
				eptr = (struct ether_header *) packet;
				ip_protocol = ntohs(eptr->ether_type);
				break;
			case DLT_LINUX_SLL:
				ip_protocol = ntohs(*(uint16_t *)(data+14));
				data += 16;
				break;
			default:
				cout<< "LOG: Unsupported link type\n";
				exit(-1);
		}

		int ip_type;
		switch (ip_protocol){
			case ETHERTYPE_IP:
				my_ip = (struct ip *)(packet + (data-packet));
				data = data + (((struct iphdr *)data)->ihl << 2);
				ip_type = my_ip->ip_p;
				break;

			case ETHERTYPE_IPV6:
				ip_type = ((struct ip6_hdr *)data)->ip6_nxt;
				data += 40;
				break;
			default:
				cerr << "LOG: Undefined type\n";
				continue;
		}

        int b;
        struct tcphdr *mytcp;
        unsigned long seq, ack;
		switch(ip_type) {
			case 6:
                #ifdef DEBUGING
                    cout << counter++ << " - TCP - ";
                #endif
                seq = ntohl(*(uint32_t *)(data+4));
                ack = ntohl(*(uint32_t *)(data+8));
                mytcp = (struct tcphdr *)data;
                if (!(mytcp->psh & 1)) {
                    #ifdef DEBUGING
                        cout << "NOT IMPLEMENTED\n";
                    #endif
                    continue;
                }
                data += (mytcp->doff*4);

				break;
			case 17:
                #ifdef DEBUGING
                    cout<<counter++ <<" - UDP - ";
                #endif
				data += 8;
				break;
			default:
				counter++;
				cerr << "Neither TCP nor UDP packet\n";
		}


        if (ip_type == 6) {
            data += 2;
        }
		struct dnshdr *my_dns = (struct dnshdr *)(data);
        my_dns->id = ntohs(my_dns->id);

		//my_dns->flags = ntohs(my_dns->flags);

		// my_dns->qr = ntohs(my_dns->qr);
		// my_dns->opcode = ntohs(my_dns->opcode);
		// my_dns->aa = ntohs(my_dns->aa);
		// my_dns->tc = ntohs(my_dns->tc);
		// my_dns->rd = ntohs(my_dns->rd);
		// my_dns->ra = ntohs(my_dns->ra);
		// my_dns->zero = ntohs(my_dns->zero);
		// my_dns->rcode = ntohs(my_dns->rcode);


		my_dns->qcount = ntohs(my_dns->qcount);
		my_dns->ancount = ntohs(my_dns->ancount);
		my_dns->nscount = ntohs(my_dns->nscount);
		my_dns->adcount = ntohs(my_dns->adcount);

        if (ip_type == 6) {
            if (my_dns->qr == 0) { // query
                tcpnum[my_dns->id] = ack;
                #ifdef DEBUGING
                    cout << "query\n";
                #endif
                continue;
            }
            else { // response
                if (tcpnum[my_dns->id] == seq) {
                    // TCP packet is not reassembled, so we can continue
                }
                else {
                    // TCP packet is reassembled
                    #ifdef DEBUGING
                        cout << "Reassembled tcp response\n";
                    #endif
                    continue;
                }
            }

        }
        #ifdef DEBUGING
		      printf("%s", (my_dns->qr == 0) ? "query   " : "response");
        #endif
        if (my_dns->ancount == 0) {
            #ifdef DEBUGING
			         cout << "\n";
            #endif
            continue;
		}
        #ifdef DEBUGING
		      printf(" *%u* \n", my_dns->ancount);
        #endif

		tmp = (u_char *)(data + 12);
		payload_offset = data - packet;
		end = data + (header.len - payload_offset);
		for (int i = 0; i < my_dns->qcount; i++) {

			// Skip the query part
			tmp = jumpToDnsAnswers(tmp);

			// Skip class and type
			tmp += 2; tmp += 2;
		}


		for (int i = 0; i < my_dns->ancount; i++) {

			string label = dnsNameToString(&tmp, data, end);
			qtype = ntohs(*(uint16_t *)tmp);

			// Skip class and ttl
			tmp += 8;

			// Get data
			answer_data = label + ' ' + RRtypes[qtype] + ' ';
			answer_data += parseDNSdata(tmp, qtype, data) + ' ';

			results.push_back(answer_data);
            #ifdef DEBUGING
                cout << "\t" << answer_data << "\n";
            #endif

			// Skip Authority RRs and Additional RRs
			tmp += ntohs(*(uint16_t *)tmp) + 2;
		}
        #ifdef DEBUGING
            cout << "\n";
        #endif
    }
    pcap_close(pcap_handler);
}

bool isDNSRequired(int type) {
	int requiredRRs[] = { RR_A, RR_NS, RR_CNAME , RR_SOA, RR_PTR , RR_MX, RR_TXT, RR_AAAA, RR_DS, RR_RRSIG, RR_SPF, RR_NSEC, RR_DNSKEY };
	for(int i = 0; i < 13; i++)
		if (type == requiredRRs[i])
			return true;
	return false;
}


u_char *jumpToDnsAnswers(u_char *label) {
	if (!label)
		return NULL;

	if (*label & 0xc0) // 0xc0 indicates there is a jump
		return label + 2;

	u_char *tmp = label;
	while (*label != '\0') {
		tmp += *label + 1;
		label = tmp;
	}
	return label + 1;
}

string dnsNameToString(u_char **label, const u_char *payload, const u_char *end) {
	u_char *tmp;

	string s="";
	while (*label < end && **label) {
		if (**label & 0xc0) { /* Pointer */
			tmp = (u_char *)payload;
			tmp += ntohs(*(uint16_t *)(*label)) & 0x3fff;
			while (tmp < end && *tmp) {
				if (*tmp & 0xc0) {
					u_char *swap = tmp;
					tmp = (u_char *)payload;
					tmp += ntohs(*(uint16_t *)(swap)) & 0x3fff;
				}

				int len = *tmp;
				tmp += 1;
				for(int i = 0; i < len; i++, tmp +=1)
					s += *tmp;
				if (*tmp == '\0') { // fix
					*label += 2;
					return s;
				}

				s += '.';
			}
			*label += 1;
		} else { /* Label */
			int len = **label;
			*label += 1;

			// added *label < end
			for(int i = 0; i < len && *label < end; i++, *label +=1) {
				s += **label;
			}
			s += '.';
		}
	}

	if (s != "")
		s.pop_back();



	return s;
}



string parseDNSdata(u_char *act, unsigned int type, const u_char *rdata) {
	int i, j, k, len;
	long additional;
	u_char *tmp = act, *here;
	string s;
	char data[128];
	uint16_t **label;
	string answer_data, answer_data2;


	switch(type) {
		case RR_A:
			tmp += 2;
			for (i = 0; i < 2; i++) {
				// cout <<  (ntohs(*(uint16_t *)tmp) >> 8) << "." << ((ntohs(*(uint16_t *)tmp) & 0xff)) << ".";
				sprintf(data, "%d", (int)(ntohs(*(uint16_t *)tmp) >> 8));
				s += data; s += ".";
				sprintf(data, "%d", (int)(ntohs(*(uint16_t *)tmp) & 0xff));
				s += data; s += ".";

				tmp += 2;
			}
			s.pop_back();
			break;

		case RR_AAAA:
			tmp += 2;
			s = inet_ntop(AF_INET6, tmp, data, 128);
			break;

		case RR_SOA:
			len = ntohs(*(uint16_t *)tmp);
			tmp += 2;
			s = "\"" +  dnsNameToString(&tmp, rdata, tmp + len - 20) + ' ';

			if (*tmp == '\0')	//fix
				tmp += 1;

			s +=  dnsNameToString(&tmp, rdata, tmp+len - 20) + ' ';

			// tmp -= 2;
			for (i = 0; i < 5; i++) {
				additional =  ntohl(*(uint32_t *)(tmp));
				sprintf(data, "%ld", additional);
				s += data;
				s += ' ';
				tmp += 4;
			}
			s.pop_back();
			s += "\"";

			break;

		case RR_TXT:
			len = ntohs(*(uint16_t *)tmp);
			tmp += 2;
			additional  = ((ntohs(*(uint16_t *)tmp) & 0xff00) >> 8);
			sprintf(data, "%d", (int)additional);
			s += "\"";
			s += data;

			s += ' ' + dnsNameToString(&tmp, rdata, tmp+additional+1) + "\"";
			break;

		case RR_NS:
		case RR_CNAME:
		case RR_PTR:
			len = ntohs(*(uint16_t *)tmp);
			tmp += 2;
			answer_data = dnsNameToString(&tmp, rdata, tmp + len);
			s = answer_data;

			break;

		case RR_MX:
			len = ntohs(*(uint16_t *)tmp);
			tmp += 2;
			additional  = ntohs(*(uint16_t *)tmp);
			sprintf(data, "%d", (int)additional);
			s += "\"";
			s += data;

			tmp += 2;
			s +=  ' ' + dnsNameToString(&tmp, rdata, tmp+len) + "\"";

			break;

        case RR_DS:
            len = ntohs(*(uint16_t *)tmp);
            tmp += 2;
            here = tmp;

            additional  = ntohs(*(uint16_t *)tmp);
            sprintf(data, "%d", (int)additional);
            s += "\"";
            s += data;
            tmp += 2;

            additional  = ntohs(*(uint16_t *)tmp) >> 8;
            sprintf(data, "%d", (int)additional);
            s += ' ';
            s += data;
            s += ' ';
            tmp += 1;

            additional  = ntohs(*(uint16_t *)tmp) >> 8;
            sprintf(data, "%d", (int)additional);
            s += ' ';
            s += data;
            s += ' ';
            tmp += 1;

            s += getSignatureName(tmp, len-4) + "\"";
            break;

        case RR_DNSKEY:
            len = ntohs(*(uint16_t *)tmp);
            tmp += 2;
            here = tmp;

            additional  = ntohs(*(uint16_t *)tmp);
			sprintf(data, "%d", (int)additional);
			s += "\"";
			s += data;
            tmp += 2;

            additional  = ntohs(*(uint16_t *)tmp) >> 8;
			sprintf(data, "%d", (int)additional);
            s += ' ';
            s += data;
            s += ' ';
            tmp += 1;

            additional  = ntohs(*(uint16_t *)tmp) >> 8;
			sprintf(data, "%d", (int)additional);
            s += ' ';
            s += data;
            s += ' ';
            tmp += 1;

            s += getSignatureName(tmp, len-4) + "\"";


            break;

        case RR_RRSIG:
            len = ntohs(*(uint16_t *)tmp);
            here = tmp;
            tmp += 2;

            additional  = ntohs(*(uint16_t *)tmp);
			sprintf(data, "%d", (int)additional);
			s += "\"";
			s += data;
            tmp += 2;

            additional  = ntohs(*(uint16_t *)tmp) >> 8;
			sprintf(data, "%d", (int)additional);
            s += ' ';
            s += data;
            s += ' ';
            tmp += 1;

            additional  = ntohs(*(uint16_t *)tmp) >> 8;
			sprintf(data, "%d", (int)additional);
            s += ' ';
            s += data;
            s += ' ';
            tmp += 1;

            for (i = 0; i < 3; i++) {
                additional =  ntohl(*(uint32_t *)(tmp));
                sprintf(data, "%ld", additional);
                s += data;
                s += ' ';
                tmp += 4;
            }

            additional  = ntohs(*(uint16_t *)tmp);
			sprintf(data, "%d ", (int)additional);
			s += data;
            tmp += 2;

            here = tmp;

            s += dnsNameToString(&tmp, rdata, tmp + len - 20) + ' ';
            tmp -= 1; // hack

            s += getSignatureName(tmp, len - (20 + (tmp-here)));

			s += "\"";
            break;
        case RR_NSEC:
            len = ntohs(*(uint16_t *)tmp);
            tmp += 2;
            s = dnsNameToString(&tmp, rdata, tmp + len) + ' ';
            tmp += 1;
            additional  = (int)ntohs(*(uint16_t *)tmp);
            sprintf(data, "%d ", (int)additional);
            tmp += 2;

            for(i = 0; i < additional; i++, tmp += 1) {
                if (*tmp == 0)
                    continue;
                for(j = 0, k = 1; j < 8; j++, k*=2) {
                    if ((*tmp & k) != 0) {
                        s += RRtypes[i*8+(8-j-1)] != "" ? (RRtypes[i*8+(8-j-1)] + ' ') : "unsupported ";
                    }
                }
            }
            s.pop_back();
            break;

        default: /* Not supported resource record types */
			len = ntohs(*(uint16_t *)tmp);
			tmp += 2 + len;

			break;

	}

	return s;
}

string toHexa(u_char *n) {
    string s;
    char data[16];
    int number = *n;
    int reminder = number % 16;
    if (reminder > 9)
        s += 'a'+(reminder-10);
    else {
        sprintf(data, "%d", reminder);
        s += data;
    }

    reminder = (number/16) % 16;
    if (reminder > 9)
        s += 'a'+(reminder-10);
    else {
        sprintf(data, "%d", reminder);
        s += data;
    }
    swap(s[0], s[1]);
    return s;
}

string getSignatureName(u_char *act, int len) {
    string s;

    u_char *tmp = act;
    for(int i = 0; i < len; i++) {
        s += toHexa(tmp);
        tmp += 1;
    }
    return s;
}
