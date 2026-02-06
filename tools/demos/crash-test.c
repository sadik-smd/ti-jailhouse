/* Inmate Crash Test Application for Jailhouse Hypervisor
 *
 * Description:
 * Application to test whether the linux inmate cell in Jailhouse hypervisor is
 * working or whether it has crashed. It can be used to send ICMP network packets 
 * to the linux inmate cell continously from root cell and check for incoming 
 * packets. The destination address will be the network interface created by the 
 * ivshmem-net module. It prints "No response received for packet x" when 
 * no incoming ICMP packet is received from inmate.
 *
 * This distribution contains contributions or derivatives under copyright
 * as follows:
 *
 * Copyright (c) 2024, Texas Instruments Incorporated
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * - Neither the name of Texas Instruments nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Force locale language to be set to English. This avoids issues when doing
 * text and string processing.
 * 
 * Authors:
 *		Paresh Bhagat <p-bhagat@ti.com>
 *		Gyan Gupta <g-gupta@ti.com>
 * 
 * Portions of this code are taken https://github.com/amitsaha/ping
 * which is licensed under Apache License 2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/ip_icmp.h>

#define PACKET_SIZE     4096
#define ICMP_ECHO       8
#define TIMEOUT         3
#define ICMP_DATA_LEN   56

typedef struct {
	int packet_count;
	int sleep_time;
	char ip_address[INET_ADDRSTRLEN];
	int quiet_mode;
} program_config;

/* Flag to check whether SIGINT signal is received */
volatile sig_atomic_t interrupted = 0;
struct sockaddr_in dest_addr;
int sockfd;
static void sigint_handler(int sig);
static void print_usage(const char*);
static int validate_ipv4_address(const char*);
static void configure_signal_handler();
static void print_options(program_config*);
static unsigned short checksum(void*,int);
static void create_socket(program_config*);
static int prepare_icmp_packet();
static void send_icmp_packet(program_config*);
static int check_icmp_reply(char*,int);
char sendpacket[PACKET_SIZE];
char recvpacket[PACKET_SIZE];

/* Signal handler for SIGINT */
static void sigint_handler(int sig) {
	(void)sig;
	interrupted = 1;
}

/* Checksum for ICMP request packet 
 Calculate 16-bit one's complement sum */
static unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;
    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

/* Print program usage */
static void print_usage(const char *program_name) {
	fprintf(stderr, "Usage: %s -c packet_count -s sleep_time -i ipv4_address -q quiet_mode\n", program_name);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "\t-c\t<packet_count>\t\tnumber of packets to be send before sleep\n");
	fprintf(stderr, "\t-s\t<sleep time>\t\tsleep time between sending packet_count packets\n");
	fprintf(stderr, "\t-i\t<destination address>\tdestination ip address (IPv4)\n");
	fprintf(stderr, "\t-q\t<quiet mode>\t\tsuppress output\n");
	fprintf(stderr, "\t-h\t<help>\t\t\tsee usage\n");
}

/* Validate IP address */
static int validate_ipv4_address(const char *ip_address) {
	return inet_pton(AF_INET, ip_address, &(dest_addr.sin_addr));
}

/* Configure SIGINT handler */
static void configure_signal_handler() {
	struct sigaction sigterm_action;
	memset(&sigterm_action, 0, sizeof(sigterm_action));
	sigterm_action.sa_handler = &sigint_handler;
	sigemptyset(&sigterm_action.sa_mask);
	sigterm_action.sa_flags = 0;
	if (sigaction(SIGINT, &sigterm_action, NULL) == -1) {
		fprintf(stderr, "Failed to set up SIGINT handler\n");
		exit(EXIT_FAILURE);
	}
}

/* Print user passed config options */
static void print_options(program_config *config) {
	fprintf(stdout, "Options:\n");
	fprintf(stdout, " Packet Count\t\t%d\n", config->packet_count);
	fprintf(stdout, " Sleep time\t\t%d\n", config->sleep_time);
	fprintf(stdout, " Destination IP\t\t%s\n", config->ip_address);
	fprintf(stdout, " Quiet Mode\t\t%s\n\n", config->quiet_mode ? "On" : "Off");
}

/* Create a socket */
static void create_socket(program_config* config) {
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    inet_pton(AF_INET, config->ip_address, &dest_addr.sin_addr);
}

/* Prepare ICMP echo request packet */
static int prepare_icmp_packet() {
	int packetsize;
	struct icmp *icmp;
	icmp = (struct icmp*)sendpacket;
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_id = getpid();
    icmp->icmp_seq = 0;
	/* 8 + 56 (data) = 64 Bytes ICMP header */
    packetsize = 8 + ICMP_DATA_LEN;
    /* Calculate ICMP checksum */
    icmp->icmp_cksum = checksum(icmp, packetsize);
	return packetsize;
}

/* Check incoming icmp packet */
static int check_icmp_reply(char *buf,int len) {
	int iphdrlen;
    struct ip *ip;
    struct icmp *icmp;
    ip = (struct ip *)buf;
    iphdrlen = ip->ip_hl << 2;
    /* Point to the ICMP header */
    icmp = (struct icmp *)(buf + iphdrlen);
    /* Total length of ICMP header */    
    len -= iphdrlen;
    /* Check ICMP header length */
    if(len < 8) {
        fprintf(stderr, "ICMP packet length is less than 8\n");
        return -1;
    }
    /* Check type of received packet */
    if(icmp->icmp_type != ICMP_ECHOREPLY) {
        return -1;
	}
    return 0;
}

/* Send icmp packets in a loop */
static void send_icmp_packet(program_config *config) {
	int response_received = 1;
	while (!interrupted && response_received) {
		for (int i = 0; i < config->packet_count && !interrupted && response_received; i++) {
			response_received = 0;
			int packetsize = prepare_icmp_packet();
			/* Send ICMP echo request packet */
        	if (sendto(sockfd, sendpacket, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) == -1) {
            	fprintf(stderr, "Sending Packet %d failed for IP address %s.\n", i+1, config->ip_address);
            	break;
        	}
			config->quiet_mode == 0 ? fprintf(stdout, "Packet %d send successfully.\n", i + 1) : 0 ;
			
			/* Receive ICMP echo reply packets with timeout */
    		struct timeval timeout;
    		fd_set readfds;
			FD_ZERO(&readfds);
            FD_SET(sockfd, &readfds);
            timeout.tv_sec = TIMEOUT;
            timeout.tv_usec = 0;
			
			if ((select(sockfd + 1, &readfds, NULL, NULL, &timeout)) > 0) {
				/* Receive the ICMP echo reply packet */
                unsigned int n = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0, NULL, NULL);
                if (n>0) {
					if(check_icmp_reply(recvpacket, n) == 0) {
                    	config->quiet_mode == 0 ? fprintf(stdout, "Response received for packet %d.\n", i + 1 ) : 0 ;
                		response_received = 1;
					}
                	else {
                    	fprintf(stderr, "Received packet is not an ICMP echo reply.\n");
                	}
        	 	} else {
                	fprintf(stderr, "Error in receiving packet!.\n");
            	}
    		} else {
                fprintf(stderr, "No response received for packet %d.\n", i + 1);
            }
		}
		/* Sleep before sending the next bunch of packets */
        sleep(config->sleep_time);
	}
}

int main(int argc, char *argv[]) {
	program_config config = {0, 0, "", 0};
    
	/* Parsing command line arguments */
	int opt;
	while ((opt = getopt(argc, argv, "c:s:i:qh")) != -1) {
		switch (opt) {
			case 'c':
				config.packet_count = atoi(optarg);
				if (config.packet_count <= 0) {
					fprintf(stderr, "Invalid value for packet count. Packet count must be a positive integer.\n");
					exit(EXIT_FAILURE);
                }
				break;
			case 's':
				config.sleep_time = atoi(optarg);
				if (config.sleep_time <= 0) {
					fprintf(stderr, "Invalid value for sleep time. Sleep time must be a positive integer.\n");
					exit(EXIT_FAILURE);
                }
				break;
			case 'i':
				if (!validate_ipv4_address(optarg)) {
					fprintf(stderr, "Invalid IPv4 address format.\n");
					exit(EXIT_FAILURE);
				}
				snprintf(config.ip_address, sizeof(config.ip_address), "%s", optarg);
				break;
			case 'q':
				config.quiet_mode = 1;
				break;
			case 'h':
				print_usage(argv[0]);
				exit(EXIT_SUCCESS);
			default:
				print_usage(argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	/* Check if all required arguments are provided */
	if (config.packet_count == 0 || config.sleep_time == 0 || config.ip_address[0] == '\0') {
		fprintf(stderr, "Missing required arguments.\n");
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	print_options(&config);
	configure_signal_handler();
	create_socket(&config);
	send_icmp_packet(&config);
	close(sockfd);
	printf("Exiting...\n");
	return 0;
}
