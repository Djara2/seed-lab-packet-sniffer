#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	printf("Got packet.\n");
}

int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf(stderr, "Please provide the NIC name.\n");
		exit(EXIT_FAILURE);
	}
	printf("NOTE: This program requires superuser privileges to execute properly. The function pcap_open_live will fail without hightened permissions.\n\n");

	char *NIC_name;
	NIC_name = argv[1];
	uint8_t NIC_name_length = (uint8_t) strlen(NIC_name);
	if (NIC_name_length < 1) {
		fprintf(stderr, "NIC cannot have empty name.\n");
		exit(EXIT_FAILURE);
	}
	printf("Sanity check: provided NIC is \"%s\".\n", NIC_name);
	
	pcap_t *handle;
	char error_buffer[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "icmp";

	bpf_u_int32 net;

	// Step 1: Open live pcap session on NIC with name eth3.
	// 	   STUDENTS NEED TO CHANGE "ETH3" TO THE NAME FOUND
	// 	   ON THEIR OWN MACHINES (using ifconfig). 
	// 	   The interface to the 10.9.0.0/24 network has a 
	// 	   prefix "br-" (if the container setup is used). 
	printf("Attempting to open live pcap session on NIC \"%s\"...", NIC_name);
	handle = pcap_open_live(NIC_name, BUFSIZ, 1, 100, error_buffer);
	if (handle == NULL) {
		fprintf(stderr, "\tFailed.\n\nFailed to open pcap live session on NIC with name \"%s\". Pointer for \"handle\" variable points to NULL.\n", NIC_name);
		exit(EXIT_FAILURE);
	}
	printf("\tSuccess!\n");

	// Step 2: Compile filter_exp into BPF pseudo-code.
	pcap_compile(handle, &fp, filter_exp, 0, net);
	if ( pcap_setfilter(handle, &fp) != 0 ) {
		pcap_perror(handle, "Error: ");
		exit(EXIT_FAILURE);
	}

	// Step 3: capture packets
	pcap_loop(handle, -1, got_packet, NULL);

	pcap_close(handle);
	return 0;
}
