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

struct UDPHeader {
	unsigned short source_port;
	unsigned short destination_port;
	unsigned short length;
	unsigned short checksum;
};

struct ICMPHeader {
	unsigned char type;		// 8 for echo request 
	unsigned char code;		// 0 for echo request
	unsigned short checksum;
	unsigned short id;		// e.g. for echo
	unsigned short sequence_number;	// e.g. for echo
};

struct PseudoHeader {
	unsigned int source_address;
	unsigned int destination_address;
	unsigned char zero;
	unsigned char protocol;
	unsigned short tcp_length;
};

// Checksum is a generic term. 
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

unsigned short compute_udp_checksum(struct IPHeader *ip_header, struct UDPHeader *udp_header, void *payload, size_t payload_length) {
	struct PseudoHeader pseudo_header = {
		.source_address 	= ip_header->source_ip,
		.destination_address    = ip_header->destination_ip,
		.zero                   = 0,
		.protocol               = IPPROTO_UDP,
		.tcp_length             = htons(sizeof(struct UDPHeader) + payload_length)
	};
	
	size_t buffer_length = sizeof(pseudo_header) + sizeof(struct UDPHeader) + payload_length;
	unsigned char *buffer = malloc(buffer_length);
	if (buffer == NULL) {
		fprintf(stderr, "Failed to allocate %zu bytes for buffer when computing UDP checksum.\n", buffer_length);
		return 0;
	}
	// copy pseudo header into packet, then udp header, then the payload
	memcpy(buffer, &pseudo_header, sizeof(pseudo_header));
	memcpy(buffer + sizeof(pseudo_header), udp_header, sizeof(struct UDPHeader));
	memcpy(buffer + sizeof(pseudo_header) + sizeof(struct UDPHeader), payload, payload_length);

	// compute checksum (same as IP checksum)
	unsigned short checksum = compute_ip_checksum(buffer, buffer_length);
	free(buffer);
	return checksum;
}

unsigned short compute_icmp_checksum(struct ICMPHeader *icmp_header, void *payload, size_t payload_length) {
	// Form "packet"/buffer from ICMP header and payload
	size_t buffer_length = sizeof(struct ICMPHeader) + payload_length;
	unsigned char *buffer = malloc(buffer_length);
	if (buffer == NULL) {
		fprintf(stderr, "Failed to allocate %zu bytes for the buffer representing the ICMP header and the payload when computing the ICMP checksum.\n", buffer_length);
		return 0;
	}
	
	memcpy(buffer, icmp_header, sizeof(struct ICMPHeader));
	memcpy(buffer + sizeof(struct ICMPHeader), payload, payload_length);

	// Compute checksum (same as IP checksum)
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
	unsigned short encapsulated_packet_length = 0;
	unsigned short ip_header_length = sizeof(struct IPHeader);
	switch (protocol) {
		case IPPROTO_TCP:
			encapsulated_packet_length = sizeof(struct TCPHeader);
			break;

		case IPPROTO_UDP:
			encapsulated_packet_length = sizeof(struct UDPHeader);
			break;

		case IPPROTO_ICMP:
			encapsulated_packet_length = sizeof(struct ICMPHeader);
			break;
		
		default:
			fprintf(stderr, "Protocol %d is not valid. Cannot calculate size of IP Header (IHL field) without being able to determine the encapsulated packet and its size. Valid protocols are TCP (%d), UPD (%d), and ICMP (%d).\n", protocol, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP);
			exit(EXIT_FAILURE);
			break;
	}
	size_t packet_total_length = ip_header_length + encapsulated_packet_length;

	printf("Sanity check:\n- Source ip: \"%s\"\n- Destination ip: \"%s\"\n- Source port: %hu\n- Destination port: %hu\n- Protocol: %d (\"%s\")\n- Payload: \"%s\"\n- Number of packets: %d\n- IP IHL: 20 (not using 0 - 40 byte option section)\n- Total packet length: %zu (%ld from IP and ", source_ip, destination_ip, source_port, destination_port, protocol, protocol_string_representation, payload, number_of_packets, packet_total_length, sizeof(struct IPHeader));
	if (protocol == IPPROTO_TCP) 
		printf("%ld from encapsulated TCP).\n", sizeof(struct TCPHeader));

	else if (protocol == IPPROTO_UDP) 
		printf("%ld from encapsulated UDP).\n", sizeof(struct UDPHeader));
	
	else if (protocol == IPPROTO_ICMP) 
		printf("%ld from encapsulated ICMP).\n", sizeof(struct ICMPHeader));
	
	else {
		fprintf(stderr, "Protocol %d is not valid. Cannot calculate size of IP Header (IHL field) without being able to determine the encapsulated packet and its size. Valid protocols are TCP (%d), UPD (%d), and ICMP (%d).\n", protocol, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP);
		exit(EXIT_FAILURE);
	}
	
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
		.version         = 4,	// IPv4
		.ihl             = 5,	// 20 bytes (no options included - min IP header size)
					// 5 * (4 byte-words) = 20 bytes

		.type_of_service = 0,
		.total_length    = ip_header_length,
		.identification  = htons(12345),
		.protocol        = protocol,

		.res             = 0,
		.df              = 0,
		.mf              = 0,
		.fragment_offset = 0, 			// no fragmentation

		.ttl             = DEFAULT_TTL,
		.checksum 	 = 0, 			// to be computed later

		.source_ip      = inet_addr(source_ip),
		.destination_ip = inet_addr(destination_ip)
	};
		
	// (3) Construct the TCP/UDP/ICMP header. This is just a matter of setting the 
	//      protocol field to 6 or 17 or 1, and then including the TCP packet immediately after the IP header.
	void *encapsulated_packet;
	switch (protocol) {
		case IPPROTO_TCP: 
			encapsulated_packet = malloc(sizeof(struct TCPHeader));
			((struct TCPHeader*) encapsulated_packet)->source_port            = htons(source_port);
			((struct TCPHeader*) encapsulated_packet)->destination_port       = htons(destination_port);
			((struct TCPHeader*) encapsulated_packet)->sequence_number        = htonl(1000);
			((struct TCPHeader*) encapsulated_packet)->acknowledgement_number = 0;
			((struct TCPHeader*) encapsulated_packet)->data_offset            = 4;
			((struct TCPHeader*) encapsulated_packet)->reserved		    = 0;
			((struct TCPHeader*) encapsulated_packet)->flags 		    = TH_SYN;
			((struct TCPHeader*) encapsulated_packet)->window_size 	    = htons(5840);
			((struct TCPHeader*) encapsulated_packet)->checksum 		    = 0; // computed later
			((struct TCPHeader*) encapsulated_packet)->urgent_pointer	    = 0;
			break;

		case IPPROTO_UDP:
			encapsulated_packet = malloc(sizeof(struct UDPHeader));
			((struct UDPHeader*) encapsulated_packet)->source_port      = htons(source_port);
			((struct UDPHeader*) encapsulated_packet)->destination_port = htons(destination_port);
			((struct UDPHeader*) encapsulated_packet)->length           = 0;
			((struct UDPHeader*) encapsulated_packet)->checksum 	      = 0;		// computed later
			break;

		case IPPROTO_ICMP: 
			encapsulated_packet = malloc(sizeof(struct ICMPHeader));
			((struct ICMPHeader*) encapsulated_packet)->type            = 8;
			((struct ICMPHeader*) encapsulated_packet)->code            = 0;
			((struct ICMPHeader*) encapsulated_packet)->checksum        = 0;
			((struct ICMPHeader*) encapsulated_packet)->id              = 1;
			((struct ICMPHeader*) encapsulated_packet)->sequence_number = 1;
			break;

		default:
			fprintf(stderr, "Protocol %d is invalid. Cannot set encapsulated header fields. Valid protocol values are TCP (%d), UDP (%d), and ICMP (%d).\n", protocol, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP);
			exit(EXIT_FAILURE); 
			break;
	}

	// (4) Combine headers into a singular packet
	char packet[packet_total_length];
	memcpy(packet, &ip_header, sizeof(struct IPHeader));
	switch (protocol) {
		case IPPROTO_TCP:
			memcpy(packet + sizeof(struct IPHeader), (struct TCPHeader*) encapsulated_packet, sizeof(struct TCPHeader));
			break;

		case IPPROTO_UDP:
			memcpy(packet + sizeof(struct IPHeader), (struct UPDHeader*) encapsulated_packet, sizeof(struct UDPHeader));
			break;

		case IPPROTO_ICMP:
			memcpy(packet + sizeof(struct IPHeader), (struct ICMPHeader*) encapsulated_packet, sizeof(struct ICMPHeader));
			break;

		default:
			fprintf(stderr, "Protocol %d is invalid. Cannot memcpy headers into overall packet to be sent.\n", protocol);
			exit(EXIT_FAILURE);
			break;
	}
	
	// (5) Compute checksums
	// (5.1) Compute IP checksum - cast as a pointer to an IP Header so that we only 
	//                             consider the size/fields of an IP header (no accidental
	//                             mutation)
	( (struct IPHeader*) packet )->checksum = 0;
	( (struct IPHeader*) packet )->checksum = compute_ip_checksum(packet, sizeof(struct IPHeader));

	// (5.2) Compute encapsulated checksum
	switch (protocol) {
		case IPPROTO_TCP:
			( (struct TCPHeader*) (packet + sizeof(struct IPHeader)))->checksum = 0;
			( (struct TCPHeader*) (packet + sizeof(struct IPHeader)))->checksum = compute_tcp_checksum( 
					(struct IPHeader*)  packet,
					(struct TCPHeader*) (packet + sizeof(struct IPHeader)),
					NULL, // No payload 
					0
				     );
			break;

		case IPPROTO_UDP:
			// avoid accidental   Skip to encapsulated UDP packet by   Set checksum
			// mutation           jumping past IP data
			( (struct UDPHeader*) (packet + sizeof(struct IPHeader)))->checksum = 0;
			( (struct UDPHeader*) (packet + sizeof(struct IPHeader)))->checksum = compute_udp_checksum( 
					(struct IPHeader*)  packet,
					(struct UDPHeader*) (packet + sizeof(struct IPHeader)),
					NULL, // No payload 
					0
				     );
			break;

		case IPPROTO_ICMP:
			// avoid accidental   Skip to encapsulated ICMP packet by   Set checksum
			// mutation           jumping past IP data
			( (struct ICMPHeader*) (packet + sizeof(struct IPHeader)))->checksum = 0;
			( (struct ICMPHeader*) (packet + sizeof(struct IPHeader)))->checksum = compute_icmp_checksum( 					                                                                              							(struct ICMPHeader*) (packet + sizeof(struct IPHeader)), 
														      NULL, // No payload 
														      0 );
			break;
		
		default:
			fprintf(stderr, "Protocol %d is invalid. Cannot calculate checksum.\n", protocol);
			exit(EXIT_FAILURE);
			break;
	}
	printf("Sanity check: checksum is ");
	switch (protocol) {
		case IPPROTO_TCP:
			printf("%hu.\n", ( (struct TCPHeader*) (packet + sizeof(struct IPHeader)) )->checksum);
			break;

		case IPPROTO_UDP: 
			printf("%hu.\n", ( (struct TCPHeader*) (packet + sizeof(struct IPHeader)) )->checksum);
			break;

		case IPPROTO_ICMP:
			printf("%hu.\n", ( (struct TCPHeader*) (packet + sizeof(struct IPHeader)) )->checksum);
			break;

		default:
			fprintf(stderr, "Protocol %d is invalid. Cannot perform sanity check.\n", protocol);
			exit(EXIT_FAILURE);
			break;
	}
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
