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
	// Use a bit field to share 1 byte for these 
	unsigned char version: 4;
	unsigned char ihl: 4;

	unsigned char type_of_service;
	unsigned short total_length;
	unsigned short identification;

	// Share 16 bits for these guys
	unsigned short res: 1;
	unsigned short df: 1;
	unsigned short mf: 1;
	unsigned short fragment_offset: 13;

	unsigned char ttl;
	unsigned char protocol;
	unsigned short checksum;
	unsigned int source_ip;
	unsigned int destination_ip;
}; 

struct TCPHeader {
	unsigned short source_port;
	unsigned short destination_port;
	unsigned int sequence_number;
	unsigned int acknowledgement_number;

	// these share an 8 bit integer.
	unsigned char data_offset: 4;
	unsigned char reserved: 4;

	unsigned char flags;
	unsigned short window_size;
	unsigned short checksum;	// tcp checksum
	unsigned short urgent_pointer;
};

struct PseudoHeader {
	unsigned int source_address;
	unsigned int destination_address;
	unsigned char zero;
	unsigned char protocol;
	unsigned short tcp_length;
};

unsigned short compute_ip_checksum(void *vdata, size_t length) {
	unsigned short *data = (unsigned short *) vdata;

	unsigned int sum = 0;
	while (length > 1) {
		// add 16 bit integer and then increment pointer
		sum += *(data++); 

		// if the sum overflows 16 bit representation...
		// (if the value is not 0 even after shifting
		//  all bits down).
		if (sum >> 16) 
			// fold overflow back.
			sum = (sum & 0xFFFF) + (sum >> 16);

		// 2 bytes have been processed.
		length -= 2;
	}
	
	// case: length is odd
	if (length) 
		sum += *(unsigned char *) data; 
	
	// flip all the bits for one's complement checksum
	return ~(unsigned short) sum;
}

unsigned short compute_tcp_checksum(struct IPHeader *ip_header, struct TCPHeader *tcp_header, void *payload, size_t payload_length) {
	// construct "pseudo header" used by TCP and UDP
	struct PseudoHeader pseudo_header = {
		.source_address      = ip_header->source_ip,
		.destination_address = ip_header->destination_ip,
		.zero                = 0,
		.protocol            = IPPROTO_TCP,
		.tcp_length          = htons(sizeof(struct TCPHeader) + payload_length)
	};
	
	// allocate a buffer for pseudo header + tcp header + payload
	size_t buffer_length = sizeof(pseudo_header) + sizeof(struct TCPHeader) + payload_length;

	char *buffer = malloc(buffer_length);
	memcpy(buffer, &pseudo_header, sizeof(pseudo_header));
	memcpy(buffer + sizeof(pseudo_header), tcp_header, sizeof(struct TCPHeader));
	memcpy(buffer + sizeof(pseudo_header) + sizeof(struct TCPHeader), payload, payload_length);

	// compute checksum
	unsigned short checksum = compute_ip_checksum(buffer, buffer_length);
	free(buffer);
	return checksum;
}

bool set_ip_header_address(struct IPHeader *ip_header, unsigned char source_or_destination, char *ip_string) {
	if (ip_header == NULL) {
		fprintf(stderr, "IP Header struct points to NULL.\n");
		return false;
	}

	if (ip_string == NULL) {
		fprintf(stderr, "IP string representation points to NULL.\n");
		return false;
	}

	if (source_or_destination == 0)
		ip_header->source_ip = inet_addr(ip_string);
	else 
		ip_header->destination_ip = inet_addr(ip_string);
		

	return true;
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
	
	// (1) Create the raw socket
	int socket_descriptor;
	socket_descriptor = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (socket_descriptor < 0) {
		fprintf(stderr, "Failed to obtain a socket descriptor.\n");
		exit(EXIT_FAILURE);
	}

	// (2) Construct the IP header. Be careful with network/host byte order
	//     (htonl and ntohl)
	struct IPHeader ip_header = {
		.version = 4,
		.ihl = 5,

		.type_of_service = 0,
		.total_length = htonl(sizeof(struct IPHeader) + sizeof(struct TCPHeader)),	
		.identification = htons(12345),

		.res = 0,
		.df  = 0,
		.mf  = 0,
		.fragment_offset = 0, // no fragmentation

		.ttl             = DEFAULT_TTL,
		.protocol        = IPPROTO_TCP,
		.checksum = 0, // to be computed later

		.source_ip      = inet_addr(source_ip),
		.destination_ip = inet_addr(destination_ip)
	};
	
	// (3) Construct the TCP/UDP/ICMP header. This is just a matter of setting the 
	//      protocol field to 6 or 17 or 1, and then including the TCP packet immediately after the IP header.
	struct TCPHeader tcp_header = {
		.source_port            = htons(1234),
		.destination_port       = htons(80),
		.sequence_number        = htonl(1000),
		.acknowledgement_number = 0,
		.data_offset            = 4,
		.reserved		= 0,
		.flags 			= TH_SYN, 
		.window_size 		= htons(5840),
		.checksum 		= 0,
		.urgent_pointer		= 0
	};

	// (4) Combine headers into a singular packet
	size_t packet_size = sizeof(struct IPHeader) + sizeof(struct TCPHeader);
	char packet[packet_size];
	memcpy(packet, &ip_header, sizeof(struct IPHeader));
	memcpy(packet + sizeof(struct IPHeader), &tcp_header, sizeof(struct TCPHeader));
	
	// (5) Compute checksums
	//     (1) Compute IP checksum
	( (struct IPHeader*) packet )->checksum = 0;
	( (struct IPHeader*) packet )->checksum = compute_ip_checksum(packet, sizeof(struct IPHeader));

	//     (2) Compute TCP checksum
	( (struct TCPHeader*) (packet + sizeof(struct IPHeader)))->checksum = 0;
	( (struct TCPHeader*) (packet + sizeof(struct IPHeader)))->checksum = compute_tcp_checksum( 
			(struct IPHeader*)  packet,
			(struct TCPHeader*) (packet + sizeof(struct IPHeader)),
			NULL, // No payload 
			0
		     );
	
	// (6) Send out the IP packet
	struct sockaddr_in destination = { 
		.sin_family = AF_INET,
		.sin_addr.s_addr = ip_header.destination_ip
	};

	if (sendto(socket_descriptor, packet, sizeof(packet), 0, (struct sockaddr *) &destination, sizeof(destination)) < 0) {
		fprintf(stderr, "Cannnot send packet.\n");
		exit(EXIT_FAILURE);
	}

	printf("Packet sent.\n");
	close(socket_descriptor);

	return 0;
}
