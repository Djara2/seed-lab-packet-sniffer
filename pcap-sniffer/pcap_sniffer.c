#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

enum ProgramParameter {
	PARAMETER_NONE,
	PARAMETER_NIC,
	PARAMETER_PROMISCUITY,
	PARAMETER_FILTER_EXPRESSION,
	PARAMETER_HELP
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	printf("Got packet.\n");
}

void display_help(void) {
	printf("Usage: pcap_sniffer [OPTION 1] [OPTION 1 SETTING]... [OPTION N] [OPTION N SETTING]\n");
	printf("Sniff packet using the pcap library.\n\n");
	printf("The --nic (-n) and --promiscuity (-p) parameters are required.\n");
	printf(" -n, --nic        \t The hardware device that the program should use for packet capture.\n");
	printf(" -p, --promiscuity\t Use 0 to disable promiscuous mode and 1 to enable promiscuous mode.\n\n");
	printf(" -f, --filter     \t Follow with an expression that works with pcap to filter\n");
	printf("                  \t packets by protocol and port destination. For example,\n");
	printf("                  \t \"icmp\" for just ICMP traffic or \"tcp dst portrange 10-100\"\n");
	printf("                  \t for just TCP traffic destined for ports on range [10, 100].\n");
	printf("Examples:\n");
	printf(" pcap_sniffer --nic br-de76e01ff5da --promiscuity 1\n");
	printf(" pcap_sniffer -n    br-de76e01ff5da -p            1\n");
}

int main(int argc, char **argv) {
	if (argc < 6) {
		display_help();
		exit(EXIT_FAILURE);
	}
	
	enum ProgramParameter previous_parameter = PARAMETER_NONE;
	char *NIC_name;
	char *filter_exp;
	uint8_t PROMISCUITY = 0;
	uint8_t hyphens = 0;
	uint8_t substring_index = 0;
	uint8_t current_token_length = 0;
	char *current_token;
	for (uint8_t i = 1; i < argc; i++) { 
		current_token = argv[i];
		current_token_length = (uint8_t) strlen(current_token);
		if (current_token_length == 0) {
			fprintf(stderr, "Parameter \"%s\" is invalid. Length of parameter cannot be less than 1.\n", current_token);
			exit(EXIT_FAILURE);
		}
		
		// Discriminate between runtime parameter and value for parameter (hyphen prefix)
		hyphens = 0;
		substring_index = 0;
		while (current_token[substring_index] == '-') {
			hyphens++;
			substring_index++;
			if (substring_index >= current_token_length) {
				fprintf(stderr, "Provided token is \"%s\" is invalid.\n", current_token);
				exit(EXIT_FAILURE);
			}
		}

		switch(hyphens) {
			// Parameter value was provided
			case 0:
				switch(previous_parameter) {
					case PARAMETER_NONE:
						fprintf(stderr, "Parameter \"%s\" is invalid. See program usage with pcap_sniffer --help\n", current_token);
						exit(EXIT_FAILURE);
						break;

					case PARAMETER_NIC:
						NIC_name = current_token;
						previous_parameter = PARAMETER_NONE;
						break;

					case PARAMETER_PROMISCUITY:
						switch(current_token[0]) {
							case '0':
								PROMISCUITY = 0;
								previous_parameter = PARAMETER_NONE;
								break;

							case '1':
								PROMISCUITY = 1;
								previous_parameter = PARAMETER_NONE;
								break;

							default:
								fprintf(stderr, "Promiscuity parameter must be either 0 or 1. Provided value \"%c\" is invalid.\n", current_token[0]);
								exit(EXIT_FAILURE);
						}
						break;

					case PARAMETER_FILTER_EXPRESSION:
						filter_exp = current_token;
						previous_parameter = PARAMETER_NONE;
						break;
				}
				break;

			// Short identifier for parameter
			case 1:
				if (current_token_length != 2) {
					fprintf(stderr, "Parameter identifier \"%s\" is either too short or too long. Short-form parameter identifiers must be exactly 2 characters long.\n", current_token);
					exit(EXIT_FAILURE);
				}
				
				switch(current_token[1]) {
					case 'n':
						previous_parameter = PARAMETER_NIC;
						break;

					case 'p':
						previous_parameter = PARAMETER_PROMISCUITY;
						break;
					
					case 'f':
						previous_parameter = PARAMETER_FILTER_EXPRESSION;
						break;

					case 'h':
						display_help();
						exit(EXIT_SUCCESS);
						break;

					default:
						fprintf(stderr, "Short-form identifier \"%s\" is invalid.\n", current_token);
						exit(EXIT_FAILURE);
						break;
				}
				break;

			// Long identifier for parameter
			case 2:
				if (current_token_length < 3) {
					fprintf(stderr, "Parameter identifier \"%s\" is invalid. Long-form parameter identifiers must be at least 3 characters long.\n", current_token);
					exit(EXIT_FAILURE);
				}
				
				// Dial pointer forward by 2 so that hyphens are ignored.
				current_token = current_token + 2;
				if 	(strcmp(current_token, "nic") == 0) 		previous_parameter = PARAMETER_NIC;
				else if (strcmp(current_token, "promiscuity") == 0)	previous_parameter = PARAMETER_PROMISCUITY;
				else if (strcmp(current_token, "filter") == 0)		previous_parameter = PARAMETER_FILTER_EXPRESSION;		
				else if (strcmp(current_token, "help") == 0) {
					display_help();
					exit(EXIT_SUCCESS);
				}
				else {
					current_token -= 2;
					fprintf(stderr, "Parameter identifier \"%s\" is invalid.\n", current_token);
					exit(EXIT_FAILURE);
				}

				break;
			
			// Too many hyphens parameters
			default:
				fprintf(stderr, "Token \"%s\" has too many hyphens. Parameter identifiers must include either 1 hyphen or 2 hyphens.\n", current_token);
				exit(EXIT_FAILURE);
				break;
		}

	}
	printf("NOTE: This program requires superuser privileges to execute properly. The function pcap_open_live will fail without hightened permissions.\n\n");
	uint8_t NIC_name_length = (uint8_t) strlen(NIC_name);
	if (NIC_name_length < 1) {
		fprintf(stderr, "NIC cannot have empty name.\n");
		exit(EXIT_FAILURE);
	}
	printf("Sanity check:\n\t- provided NIC is \"%s\"\n\t- provided promiscuity value is %u\n\t- provided filter expression is \"%s\"\n\n", NIC_name, PROMISCUITY, filter_exp);
	
	pcap_t *handle;
	char error_buffer[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	// char filter_exp[] = "icmp"; // see line 43

	bpf_u_int32 net;

	// Step 1: Open live pcap session on NIC with name eth3.
	// 	   STUDENTS NEED TO CHANGE "ETH3" TO THE NAME FOUND
	// 	   ON THEIR OWN MACHINES (using ifconfig). 
	// 	   The interface to the 10.9.0.0/24 network has a 
	// 	   prefix "br-" (if the container setup is used). 
	printf("Attempting to open live pcap session on NIC \"%s\"...", NIC_name);
	handle = pcap_open_live(NIC_name, BUFSIZ, PROMISCUITY, 100, error_buffer);
	if (handle == NULL) {
		fprintf(stderr, "\tFailed.\n\nFailed to open pcap live session on NIC with name \"%s\". Pointer for \"handle\" variable points to NULL.\n", NIC_name);
		exit(EXIT_FAILURE);
	}
	printf("\tSuccess!\n");

	// Step 2: Compile filter_exp into BPF pseudo-code.
	printf("Attempting to compile into BPF pseudocode...");	
	pcap_compile(handle, &fp, filter_exp, 0, net);
	printf("\tSuccess.\n");
	printf("Attemping to set compiled pcap filter...");
	if ( pcap_setfilter(handle, &fp) != 0 ) {
		printf("\tFailed.\n");
		pcap_perror(handle, "Error: ");
		exit(EXIT_FAILURE);
	}
	printf("\tSuccess!\n");

	// Step 3: capture packets
	pcap_loop(handle, -1, got_packet, NULL);

	pcap_close(handle);
	return 0;
}
