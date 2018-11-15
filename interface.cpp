#include "interface.h"

extern const char *filter;
extern list<string> results;
extern map<int, string> RRtypes;

// #define DEBUGING 1

void listenToInterface(argument a) {
    char err_buff[PCAP_BUFFER_SIZE];
    pcap_t *pcap_handler;
    const u_char *packet;
    struct pcap_pkthdr header;
    struct ether_header *eptr;
    struct ip *my_ip;
	unsigned counter = 1;
	struct bpf_program fp;
    char *device;
    bpf_u_int32 netaddr;            // network address configured at the input device
    bpf_u_int32 mask;               // network mask of the input device
    map<long,long> tcpnum;

    // Open device to sniff data
    if ((device = pcap_lookupdev(err_buff)) == NULL)
        errorMsg(R_DEVICE_ERROR, (char *)"Can not open device");

    // get IP address and mask of the sniffing interface
    if (pcap_lookupnet(a.interface.c_str(), &netaddr, &mask, err_buff) == -1)
        errorMsg(R_LOOKUPNET_FAIL, (char *)"pcap_lookupnet fail");

    if ((pcap_handler = pcap_open_live(a.interface.c_str(), PCAP_BUFFER_SIZE, 1, 2048, err_buff)) == NULL) {
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
	for (;;) {
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
		//cout << "AD \n";
	}
    pcap_close(pcap_handler);
}
