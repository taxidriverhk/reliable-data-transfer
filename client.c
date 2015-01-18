#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>
#include "packet.h"

#define SENT 0
#define RECEIVED 1

int BUF_SIZE = 1024;
double LOSS_PROB = 0;
double CORRUPT_PROB = 0;


/*
 * error - wrapper for perror
 */
void error(char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

double random_num() {
    return (double) rand()/(double) RAND_MAX;
}


void
print_packet_info(packet_t p, int mode)
{
	printf("Receiver:	");
    
	switch(p.type)
	{
		case DATA:
			printf("DATA"); break;
		case ACK:
			printf("ACK"); break;
		case FINACK:
			printf("FINACK"); break;
		case ERROR:
			printf("ERROR"); break;
	}
    
	if(mode == SENT)
		printf(" sent ");
	else if(mode == RECEIVED)
		printf(" received ");
    
	printf("seq#%d, ", p.seq_num);
	printf("ACK#%d, ", p.ack_num);
	printf("FIN %d, ", p.fin);
	printf("content-length: %d\n", p.payload_length);
}


int main(int argc, char **argv) {
    int socketfd, portno, n, expected_seq_num;
    int serverlen;
    struct sockaddr_in serveraddr;
    struct hostent *server;
    char *hostname, *filename;
    char buf[BUF_SIZE];
    FILE* resource;
    struct timeval tv;
    fd_set readfds;
    int select_n;
    int rv;
    int loop;
    
    /* check command line arguments */
    if (argc != 6) {
        fprintf(stderr,"usage: %s <hostname> <port> <filename> <LostProb> <CorruptProb>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    hostname = argv[1];
    portno = atoi(argv[2]);
    filename = argv[3];
    LOSS_PROB = atof(argv[4]);
    CORRUPT_PROB = atof(argv[5]);
    
    /* socket: create the socket */
    socketfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketfd < 0)
        error("ERROR opening socket");
    
    /* gethostbyname: get the server's DNS entry */
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host as %s\n", hostname);
        exit(EXIT_FAILURE);
    }
    
    /* build the server's Internet address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons(portno);
    
    
    
    
    //////////////////////////////////////////////////////////////////////////////
    
    packet_t rspd_pkt;
    bzero((char *) &rspd_pkt, sizeof(rspd_pkt));
    expected_seq_num = 0;
    
    packet_t req_pkt;
    bzero((char *) &req_pkt, sizeof(req_pkt));
    strcpy(req_pkt.payload, filename);
    resource = fopen(strcat(filename, "_copy"), "wb");
    // bzero((char *) &req_pkt, sizeof(req_pkt));
    // req_pkt.payload_length = sizeof(int) * 3;
    // req_pkt.type = ACK;
    // req_pkt.seq_num = expected_seq_num - 1;
    
    
    
    /* build the request */
    req_pkt.payload_length = strlen(filename)-5;
    req_pkt.seq_num = 0;
    req_pkt.ack_num = 0;
    req_pkt.fin = 0;
    req_pkt.type = DATA;
    
    /* send the request to the server */
    serverlen = sizeof(serveraddr);
    n = sendto(socketfd, &req_pkt, sizeof(req_pkt), 0, (struct sockaddr*) &serveraddr, serverlen);
    if (n < 0)
        error("ERROR in sendto");
    printf("Requested file %s\n", req_pkt.payload);
    print_packet_info(req_pkt,SENT);
    
    FD_ZERO(&readfds);
    FD_SET(socketfd, &readfds);
    select_n = socketfd + 1;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    
    while (1) {
        rv = select(select_n, &readfds, NULL, NULL, &tv);
        if (rv == -1) {
            error("ERROR in select");
        }
        else if (rv == 0) {
            printf("Timeout, resend request. ");
            n = sendto(socketfd, &req_pkt, sizeof(req_pkt), 0, (struct sockaddr*) &serveraddr, serverlen);
            if (n < 0)
                error("ERROR in sendto");
            printf("Requested file %s\n", req_pkt.name);
            print_packet_info(req_pkt,SENT);

        }
        //First packet received.
        else{
            recvfrom(socketfd, &rspd_pkt, sizeof(rspd_pkt), 0, (struct sockaddr*) &serveraddr, (socklen_t*) &serverlen);
            print_packet_info(rspd_pkt,RECEIVED);
            
            fwrite(rspd_pkt.payload, 1, rspd_pkt.payload_length, resource);
            req_pkt.seq_num = rspd_pkt.ack_num;
            req_pkt.ack_num = rspd_pkt.seq_num + rspd_pkt.payload_length;
            req_pkt.fin = 0;
            req_pkt.type = ACK;
            req_pkt.payload_length = 0;
            
            
            if (sendto(socketfd, &req_pkt, sizeof(req_pkt), 0, (struct sockaddr*) &serveraddr, serverlen) < 0)
                error("ERROR acking");
            else
                print_packet_info(req_pkt,SENT);
            break;
        }
    }
    
    
    
    
    
    //////////////////////////////////////////////////////////////////////////////
    
    srand(time(NULL));
    while (1) {
        tv.tv_sec = 8;
        tv.tv_usec = 0;
        rv = select(select_n, &readfds, NULL, NULL, &tv);
        if (rv == -1) {
            error("ERROR in select");
        }
        //receiver time out, close connection
        else if(rv == 0){
            printf("Receiver: Timeout, close connection !!!\n");
            break;
        }
        //detects that socket has some data to read
        else{
            if (recvfrom(socketfd, &rspd_pkt, sizeof(rspd_pkt), 0, (struct sockaddr*) &serveraddr, (socklen_t*) &serverlen) < 0 || random_num() < LOSS_PROB) {
                printf("Packet lost!\n");
            }
            else if (random_num() < CORRUPT_PROB) {
                printf("Packet corrupted!\n");
                if (sendto(socketfd, &req_pkt, sizeof(req_pkt), 0, (struct sockaddr*) &serveraddr, serverlen) < 0)
                    error("ERROR responding to corrupt packet");
            }
            //Packet received
            else {
                print_packet_info(rspd_pkt,RECEIVED);
                
                //receive packet, need to check if it is in order
                if (rspd_pkt.seq_num != req_pkt.ack_num ){
                    if (sendto(socketfd, &req_pkt, sizeof(req_pkt), 0, (struct sockaddr*) &serveraddr, serverlen) < 0)
                        error("ERROR acking");
                    else
                        print_packet_info(req_pkt,SENT);
                    
                }
                else{
                    //Receive 1st FIN packet, send back FINACK
                    if ((rspd_pkt.fin == 1)&&(rspd_pkt.type == DATA)) {
                        req_pkt.seq_num++;
                        req_pkt.ack_num++;
                        req_pkt.fin =1;
                        req_pkt.type = FINACK;
                        
                        if (sendto(socketfd, &req_pkt, sizeof(req_pkt), 0, (struct sockaddr*) &serveraddr, serverlen) < 0)
                            error("ERROR acking");
                        else
                            print_packet_info(req_pkt,SENT);
                        
                    }
                    //Receive 2nd FIN packet
                    else if ((rspd_pkt.fin == 1)&&(rspd_pkt.type == FINACK)){
                        break;
                    }
                    else{
                        fwrite(rspd_pkt.payload, 1, rspd_pkt.payload_length, resource);
                        req_pkt.seq_num++;
                        req_pkt.ack_num = rspd_pkt.seq_num + MAX_PACKET_SIZE ;
                        req_pkt.fin = 0;
                        req_pkt.type = ACK;
                        req_pkt.payload_length = 0;
                        
                        if (sendto(socketfd, &req_pkt, sizeof(req_pkt), 0, (struct sockaddr*) &serveraddr, serverlen) < 0)
                            error("ERROR acking");
                        else
                            print_packet_info(req_pkt,SENT);
                    }
                    
                }
            }
        }
        
    }
    fclose(resource);
    printf("Receiver: close connection\n");
    return 0;
}
