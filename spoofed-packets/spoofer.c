#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <time.h>

#define MAX_PACKET_SIZE 4096
#define DEFAULT_TTL 64

/* Using raw sockets is quite striaght forward; it involves 4 steps:
 * (1) Create a raw socket
 * (2) Set socket option (setsockopt) 
 * (3) Construct the packet
 * (4) Send out the packet through the raw socket. 
 */

enum ProgramParameter {
	PARAMETER_NONE,
	PARAMETER_SOURCE_IP,
	PARAMETER_DESTINATION_IP,
	PARAMETER_SOURCE_PORT,
	PARAMETER_DESTINATION_PORT,
	PARAMETER_PROTOCOL,
	PARAMETER_PAYLOAD,
	PARAMETER_NUMBER_OF_PACKETS
};

int main(int argc, char **argv) {
	if (argc < 6) {
		fprintf(stderr, "Insufficient arguments.\n");
		return 1;
	}
	
	// program variables
	int protocol = 0;
	char *protocol_string_representation;
	unsigned short source_port = 0;
	unsigned short destination_port = 0;
	char *source_ip;
	char *destination_ip;
	char *payload;
	int number_of_packets = 0;

	// command line parsing variables
	enum ProgramParameter previous_parameter;
	previous_parameter = PARAMETER_NONE;
	char *current_token;
	unsigned short current_token_length = 0;
	unsigned char hyphen_count = 0;
	for (unsigned char i = 1; i < argc; i++) {
		current_token = argv[i];
		current_token_length = (unsigned short) strlen(argv[i]);
		
		hyphen_count = 0;
		while (current_token[hyphen_count] == '-')
			hyphen_count++;

		switch (hyphen_count) {
			case 0:

				switch (previous_parameter) {
					case PARAMETER_NONE:
						fprintf(stderr, "Value \"%s\" is provided without parameter for which the value should be set.\n", current_token);
						exit(EXIT_FAILURE);
						break;

					case PARAMETER_SOURCE_IP:
						source_ip = current_token;
						break;

					case PARAMETER_DESTINATION_IP:
						destination_ip = current_token;
						break;

					case PARAMETER_SOURCE_PORT:
						source_port = (unsigned short) atoi(current_token);
						break;

					case PARAMETER_DESTINATION_PORT:
						destination_port = (unsigned short) atoi(current_token);
						break;

					case PARAMETER_PROTOCOL: 
						protocol_string_representation = current_token;
						if (strcmp(current_token, "tcp") == 0) {
							protocol = IPPROTO_TCP;
						}
						else if (strcmp(current_token, "udp") == 0) {
							protocol = IPPROTO_UDP;
						}
						else if (strcmp(current_token, "icmp") == 0) {
							protocol = IPPROTO_ICMP;
						}
						else {
							fprintf(stderr, "Protocol \"%s\" is invalid. Valid values are \"tcp\", \"udp\", and \"icmp\".\n", current_token);
							exit(EXIT_FAILURE);
						}
						break;
					
					case PARAMETER_PAYLOAD:
						payload = current_token;
						break;
					
					case PARAMETER_NUMBER_OF_PACKETS:
						number_of_packets = atoi(current_token);
						break;

					default:
						fprintf(stderr, "previous_parameter value of %d is unhandled.\n", previous_parameter);
						exit(EXIT_FAILURE);
				}

				// Reset so that there is no parameter currently set, since a parameter value literal 
				// was just provided.
				previous_parameter = PARAMETER_NONE;
				break;

			// short form ID
			case 1:
				if(current_token_length != 2) {
					fprintf(stderr, "Short form parameter identifiers must be exactly 2 characters long.\n");
					exit(EXIT_FAILURE);
				}

				switch(current_token[1]) {
					case 's':	// source ip
						previous_parameter = PARAMETER_SOURCE_IP;
						break;

					case 'd':	// destination ip
						previous_parameter = PARAMETER_DESTINATION_IP;
						break;

					case 'S':	// source port
						previous_parameter = PARAMETER_SOURCE_PORT;
						break;

					case 'D':	// destination port
						previous_parameter = PARAMETER_DESTINATION_PORT;
						break;

					case 'p':	// protocol
						previous_parameter = PARAMETER_PROTOCOL;
						break;
					
					case 'l':	// payload
						previous_parameter = PARAMETER_PAYLOAD;
						break;

					case 'n':	// number of packets
						previous_parameter = PARAMETER_NUMBER_OF_PACKETS;
						break;

					default:
						fprintf(stderr, "Parameter identifier \"%s\" is invalid. Valid parameter identifiers are \"-s\" for source IP, \"-S\" for source port, \"-d\" for destination IP, \"-D\" for destination port, \"-p\" for protocol, \"-l\" for payload, and \"-n\" for the number of packets.\n", current_token);
						exit(EXIT_FAILURE);
				}
				break;
			
			// long form ID
			case 2:
				if (current_token_length < 3) {
					fprintf(stderr, "Parameter identifier \"%s\" is invalid. Long-form parameter identifiers must be at least 3 characters long.\n", current_token);
					exit(EXIT_FAILURE);
				}
				// dial pointer forward by 2 to skip the hyphens
				current_token += 2;
				if (strcmp(current_token, "source-ip") == 0)
					previous_parameter = PARAMETER_SOURCE_IP;

				else if (strcmp(current_token, "destination-ip") == 0)	
					previous_parameter = PARAMETER_DESTINATION_IP;

				else if (strcmp(current_token, "source-port") == 0)	
					previous_parameter = PARAMETER_SOURCE_PORT;

				else if (strcmp(current_token, "destination-port") == 0)	
					previous_parameter = PARAMETER_DESTINATION_PORT;

				else if (strcmp(current_token, "protocol") == 0)	
					previous_parameter = PARAMETER_PROTOCOL;

				else if (strcmp(current_token, "payload") == 0)	
					previous_parameter = PARAMETER_PAYLOAD; 

				else if (strcmp(current_token, "number") == 0)	
					previous_parameter = PARAMETER_NUMBER_OF_PACKETS;

				else {
					current_token -= 2;
					fprintf(stderr, "Parameter identifier \"%s\" is invalid. Valid identifiers are \"--source-ip\", \"--destination-ip\", \"--source-port\", \"--destination-port\", \"--payload\", and \"--number\".", current_token);
					exit(EXIT_FAILURE);
				}
				break;

			default:
				fprintf(stderr, "Parameter \"%s\" has too many consecutive hyphens.\n", current_token);
				exit(EXIT_FAILURE);
				break;
		}
				
	}
	printf("Sanity check:\n- Source ip: \"%s\"\n- Destination ip: \"%s\"\n- Source port: %hu\n- Destination port: %hu\n- Protocol: %d (\"%s\")\n- Payload: \"%s\"\n- Number of packets: %d\n\n", source_ip, destination_ip, source_port, destination_port, protocol, protocol_string_representation, payload, number_of_packets);
	return 0;
}
