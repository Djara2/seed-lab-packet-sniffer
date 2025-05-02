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
#include <stdbool.h>

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

enum ProgramError {
	ERROR_NONE,
	ERROR_NULL_POINTER
};

struct IPHeader {
	unsigned char version_and_hlen;
	unsigned char type_of_service;
	unsigned short total_length;
	unsigned short identification;
	unsigned short res_df_mf_fragment_offset;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short header_checksum;
	unsigned char source_ip[4];
	unsigned char destination_ip[4];
	unsigned char *option;
	unsigned char option_length;	// do not write to buffer
	unsigned char *data;
	unsigned short data_length;	// do not write to buffer
};

unsigned char get_res_bit(struct IPHeader *ip_header, enum ProgramError *error) {
	if (ip_header == NULL) {
		fprintf(stderr, "IP header struct points to NULL.\n");
		(*error) = ERROR_NULL_POINTER;
		return 0;
	}
	unsigned short ignore_lower_bits_bitmask = 0x8000;
	unsigned short res = ip_header->res_df_mf_fragment_offset & ignore_lower_bits_bitmask;
	(*error) = ERROR_NONE;
	if (res == 0) return 0;
	else 	      return 1;
}

unsigned char get_df_bit(struct IPHeader *ip_header, enum ProgramError *error) {
	if (ip_header == NULL) {
		fprintf(stderr, "IP header struct points to NULL.\n");
		(*error) = ERROR_NULL_POINTER;
		return 0;
	}

	unsigned short ignore_other_bits_bitmask = 0x4000;
	unsigned short df = ip_header->res_df_mf_fragment_offset & ignore_other_bits_bitmask;
	(*error) = ERROR_NONE;
	if (df == 0) return 0;
	else	     return 1;
}

unsigned char get_mf_bit(struct IPHeader *ip_header, enum ProgramError *error) {
	if (ip_header == NULL) {
		fprintf(stderr, "IP header struct points to NULL.\n");
		(*error) = ERROR_NULL_POINTER;
		return 0;
	}

	unsigned short ignore_other_bits_bitmask = 0x2000;
	unsigned short mf = ip_header->res_df_mf_fragment_offset & ignore_other_bits_bitmask;
	(*error) = ERROR_NONE;
	if (mf == 0) return 0;
	else	     return 1;
}

bool set_res_low(struct IPHeader *ip_header) {
	if (ip_header == NULL) {
		fprintf(stderr, "IP header struct points to NULL.\n");
		return false;
	}
	unsigned short res;
	res = ip_header->res_df_mf_fragment_offset;
	res = res & (~  (1 << 15));
	ip_header->res_df_mf_fragment_offset = res;
	return true;
}

bool set_res_high(struct IPHeader *ip_header) {
	if (ip_header == NULL) {
		fprintf(stderr, "IP Header struct points to NULL.\n");
		return false;
	}
	unsigned short res;
	res = ip_header->res_df_mf_fragment_offset;
	res = res | (1 << 15); 
	ip_header->res_df_mf_fragment_offset = res;

	return true;
}

bool set_df_low(struct IPHeader *ip_header) {
	if (ip_header == NULL) {
		fprintf(stderr, "IP header struct points to NULL.\n");
		return false;
	}
	unsigned short df;
	df = ip_header->res_df_mf_fragment_offset;
	df = df & (~  (1 << 14));
	ip_header->res_df_mf_fragment_offset = df;
	return true;
}

bool set_df_high(struct IPHeader *ip_header) {
	if (ip_header == NULL) {
		fprintf(stderr, "IP Header struct points to NULL.\n");
		return false;
	}
	unsigned short df;
	df = ip_header->res_df_mf_fragment_offset;
	df = df | (1 << 14); 
	ip_header->res_df_mf_fragment_offset = df;

	return true;
}

bool set_mf_low(struct IPHeader *ip_header) {
	if (ip_header == NULL) {
		fprintf(stderr, "IP header struct points to NULL.\n");
		return false;
	}
	unsigned short mf;
	mf = ip_header->res_df_mf_fragment_offset;
	mf = mf & (~  (1 << 13));
	ip_header->res_df_mf_fragment_offset = mf;
	return true;
}

bool set_mf_high(struct IPHeader *ip_header) {
	if (ip_header == NULL) {
		fprintf(stderr, "IP Header struct points to NULL.\n");
		return false;
	}
	unsigned short mf;
	mf = ip_header->res_df_mf_fragment_offset;
	mf = mf | (1 << 13); 
	ip_header->res_df_mf_fragment_offset = mf;

	return true;
}

bool set_fragment_bits(struct IPHeader *ip_header, unsigned short v) {
	if (v > 8192)
		fprintf(stderr, "The provided value of %hu is too large for 13 bit representation. It will be modded by 8192 to ensure it falls on the appropriate range of [0, 8191].\n", v);

	// ensure it falls on range [0, 8192]
	v = v % 8192;

	// clear the existing fragment bits, but maintain the flag bits
	unsigned short ignore_flags_bitmask = 0xe000;
	ip_header->res_df_mf_fragment_offset = ip_header->res_df_mf_fragment_offset & ignore_flags_bitmask;
	
	// define new value for whole thing
	unsigned short new_res_df_mf_fragment_offset_value = ignore_flags_bitmask + v;
	ip_header->res_df_mf_fragment_offset = new_res_df_mf_fragment_offset_value;

	return true;
}

unsigned short get_fragment_bits(struct IPHeader *ip_header) {
	unsigned short ignore_flags_bitmask = 0x1fff;
	unsigned short fragment_bits = ignore_flags_bitmask & ip_header->res_df_mf_fragment_offset;
	return fragment_bits;
}

int main(int argc, char **argv) {
	printf("NOTE that this program requires superuser privileges.\n");
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

	int socket_descriptor;
	struct sockaddr_in sin;
	char buffer[1024];	// representation of IP header
	unsigned short buffer_length = 0;
	socket_descriptor = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (socket_descriptor < 0) {
		fprintf(stderr, "Failed to obtain a socket descriptor.\n");
		exit(EXIT_FAILURE);
	}

	sin.sin_family = AF_INET;
	// Construct the IP header. Be careful with network/host byte order
	// (htonl and ntohl)
	buffer[
	
	
	// Send out the IP packet
	if (sendto(socket_descriptor, buffer, buffer_length, 0, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
		fprintf(stderr, "Cannnot send packet.\n");
		exit(EXIT_FAILURE);
	}
	return 0;
}
