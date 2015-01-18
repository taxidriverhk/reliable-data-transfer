#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "packet.h"

#define DEFAULT_WINDOW_SIZE 10
#define DEFAULT_TIMEOUT_LIMIT 5000 /* seconds */

#define SENT 0
#define RECEIVED 1

void 
error(char *msg)
{
    perror(msg);
    exit(1);
}

int 
min(int a, int b)
{
	return a < b ? a : b;
}

void
print_packet_info(packet_t p, int mode)
{
	printf("Sender:	");

	switch(p.type)
	{
		case DATA:
			printf("DATA"); break;
		case ACK:
			printf("ACK"); break;
		case FINACK:
			printf("FINACK"); break; 
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

static void
process_file_request(int sockfd, int window_size, 
                    struct sockaddr_in cli_addr, socklen_t clilen,
		              float prob_loss, float prob_corruption)
{
    int window_pos;
    int packets_sent = 0, num_packets;
    int oldest_ack_num, timeout_mode = 0;
    int current_seq_num, current_ack_num;

    int packet_lost, packet_corrupted;
    int resend_packets = 0;

    time_t timer;
    packet_t req_packet, data_packet, ack_packet, complete_packet, finack_packet;
    packet_t *window = (packet_t *) malloc(window_size * sizeof(packet_t));
    FILE *requested_file;
    struct stat requested_file_stat;

    printf("Sender: waiting for file request\n");
    /* Try to receive datagram from the client */
    if(recvfrom(sockfd, &req_packet, 
                sizeof(req_packet), 0,
                (struct sockaddr *) &cli_addr, (socklen_t *) &clilen) < 0)
        error("ERROR on receiving datagram from client");

    print_packet_info(req_packet, RECEIVED);

    printf("Sender: File requested is \"%s\"\n", req_packet.payload);
    printf("..................................................\n");

    /* Try to get the file requested */
    requested_file = fopen(req_packet.payload, "rb");
    if(requested_file == NULL)
        error("ERROR in opening file\n");

    /* Get the information about the file */
    stat(req_packet.payload, &requested_file_stat);
    /* Calculate the number of packets to be transmitted */
    num_packets = requested_file_stat.st_size / MAX_PACKET_SIZE;
    /* Last packet for residual data */
    if(requested_file_stat.st_size % MAX_PACKET_SIZE != 0)
        num_packets++;

    /* Set the timer to keep track of timeout */
    timer = time(NULL);
    /* Send the packets in window */
    oldest_ack_num = req_packet.ack_num;
    current_seq_num = req_packet.ack_num;
    current_ack_num = req_packet.seq_num + req_packet.payload_length;
    for(window_pos = 0; window_pos < window_size; window_pos++)
    {
        /* Fill the buffer with the packets */
        window[window_pos].type = DATA;
        window[window_pos].seq_num = current_seq_num;
        window[window_pos].ack_num = current_ack_num;
        window[window_pos].fin = 0;
        /* fread() will advance its stream pointer by MAX_PACKET_SIZE after every call */
        window[window_pos].payload_length = fread(window[window_pos].payload, 1, MAX_PACKET_SIZE, requested_file);

        if(window[window_pos].payload_length == 0)
            continue;

        /* Try to send the packet back to the client */
        packet_corrupted = rand() % 100;
        packet_lost = rand() % 100;
        if(sendto(sockfd, &window[window_pos], 
                    sizeof(packet_t), 0, 
                    (struct sockaddr *) &cli_addr, clilen) < 0
            || packet_corrupted < (int) 100 * prob_loss
            || packet_lost < (int) 100 * prob_corruption)
        {
            printf("Sender: (DATA lost or corrupted) Unable to send the packet\n");
            resend_packets = 1;
        }
        print_packet_info(window[window_pos], SENT);

        current_seq_num += window[window_pos].payload_length;
        current_ack_num += 1;
    }

    /* Process all other unACKed packets */
    while(packets_sent < num_packets)
    {
        /* Timeout occurs, so resend the packets in window */
        if(resend_packets)
            goto resend_packets_in_window;

        packet_corrupted = rand() % 100;
        packet_lost = rand() % 100;
        if(timeout_mode || time(NULL) > timer + DEFAULT_TIMEOUT_LIMIT
            || packet_corrupted < (int) (100 * prob_loss)
            || packet_lost < (int) (100 * prob_corruption))
        {
            timer = time(NULL);
            timeout_mode = 0;
            oldest_ack_num = window[0].ack_num;
            printf("Sender: (ACK lost or corrupted) Timeout\n");

            resend_packets_in_window:
            for(window_pos = 0; window_pos < window_size; window_pos++)
            {
                packet_corrupted = rand() % 100;
                packet_lost = rand() % 100;

                if(window[window_pos].payload_length == 0)
                    continue;

                if(sendto(sockfd, &window[window_pos], 
                    sizeof(packet_t), 0, 
                    (struct sockaddr *) &cli_addr, clilen) < 0
                    || packet_corrupted < (int) (100 * prob_loss)
                    || packet_lost < (int) (100 * prob_corruption))
                {
                    printf("Sender: (DATA lost or corrupted) Unable to send the packet\n");
                    resend_packets = 1;
                }
                print_packet_info(window[window_pos], SENT);
            }
            resend_packets = 0;
            continue;
        }
        /* ACK is received from client, so slide the window */
        if(recvfrom(sockfd, &ack_packet, 
                    sizeof(ack_packet), 0, (struct sockaddr *) &cli_addr,
                    (socklen_t *) &clilen) > 0)
        {
            /* If the ACK received is not for the oldest unACK packet, 
            then assume timeout occurs */
            if(ack_packet.seq_num < oldest_ack_num)
            {
                timeout_mode = 1;
                continue;
            }
            else
            {
                timer = time(NULL);
                oldest_ack_num = ack_packet.seq_num + 1;
            }
            print_packet_info(ack_packet, RECEIVED);

            /* Slide the window and get the new data packet */
            printf("Sender: sliding window\n");
            for(window_pos = 0; window_pos < window_size-1; window_pos++)
                window[window_pos] = window[window_pos+1];
            /* Put the new packet into the window (if there is data to read) */
            data_packet.type = DATA;
            data_packet.seq_num = current_seq_num;
            data_packet.ack_num = current_ack_num;
            data_packet.fin = 0;
            data_packet.payload_length = fread(data_packet.payload, 1, MAX_PACKET_SIZE, requested_file);

            window[window_size-1] = data_packet;

            packet_corrupted = rand() % 100;
            packet_lost = rand() % 100;

            if(data_packet.payload_length != 0)
            {
                if(sendto(sockfd, &data_packet, 
                    sizeof(packet_t), 0, 
                    (struct sockaddr *) &cli_addr, clilen) < 0
                    || packet_corrupted < (int) 100 * prob_loss
                    || packet_lost < (int) 100 * prob_corruption)
                {
                    printf("Sender: (DATA lost or corrupted) Unable to send the packet\n");
                    resend_packets = 1;
                }
                print_packet_info(data_packet, SENT);

                current_seq_num += data_packet.payload_length;
                current_ack_num += 1;
            }

            packets_sent++;
        }
    }

    /* The file was sent completely, so send a packet to the client
        notifying that the transmission is complete */
    printf("Sender: file transfer complete\n");

    complete_packet.type = DATA;
    complete_packet.seq_num = ack_packet.ack_num;
    complete_packet.ack_num = ack_packet.seq_num + 1;
    complete_packet.fin = 1;
    complete_packet.payload_length = 0;
    /* Try to send the packet */
	receive_finack:
    if(sendto(sockfd, &complete_packet, 
                sizeof(packet_t), 0, 
                (struct sockaddr *) &cli_addr, clilen) < 0)
        error("ERROR sending packet");
    print_packet_info(complete_packet, SENT);

    /* The client should send back an FINACK packet to the server */
    if(recvfrom(sockfd, &finack_packet, 
                sizeof(finack_packet), 0,
                (struct sockaddr *) &cli_addr, (socklen_t *) &clilen) < 0)
        error("ERROR on receiving datagram from client");
    if(finack_packet.type != FINACK)
	{
		printf("Sender: (FINACK lost or corrupted) Timeout\n");
        goto receive_finack;
	}
    print_packet_info(finack_packet, RECEIVED);

    current_seq_num = finack_packet.ack_num;
    current_ack_num = finack_packet.seq_num + 1;

    /* Finally, send an FINACK packet to the client to finish the transmission */
    complete_packet.type = FINACK;
    complete_packet.seq_num = current_seq_num;
    complete_packet.ack_num = current_ack_num;
    complete_packet.fin = 1;
    complete_packet.payload_length = 0;
    /* Try to send the packet */
    if(sendto(sockfd, &complete_packet, 
                sizeof(packet_t), 0, 
                (struct sockaddr *) &cli_addr, clilen) < 0)
        error("ERROR sending packet");
    print_packet_info(complete_packet, SENT);

    /* Cleanup */
    free(window);
    fclose(requested_file);

    printf("Sender: close connection\n");
}

static void
setup_and_run_server(int portno, int window_size, float prob_loss, float prob_corruption)
{
    int sockfd;
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t clilen;

    /* Try to create an unnamed socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0)
        error("ERROR opening socket");

    /* Initialize the server */
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(portno);

    /* Try to bind the socket created to the server */
    if(bind(sockfd, 
        (struct sockaddr *) &serv_addr,
        sizeof(serv_addr)) < 0)
        error("ERROR on binding");

    clilen = sizeof(cli_addr);

    /* Wait for the client to send the file request and the server will process it */
    process_file_request(sockfd, window_size, cli_addr, clilen, prob_loss, prob_corruption);
}

int
main(int argc, char **argv)
{
    int portno, window_size;
    float prob_loss, prob_corruption;

    /* Port number must be specified */
    if(argc != 5)
    {
        fprintf(stderr, "Usage: %s <port> <window-size> <loss-probability> <corruption-probability>\n", argv[0]);
        return 1;
    }
    /* If the three optional arguments exist */
    
    window_size = atoi(argv[2]);
    prob_loss = atof(argv[3]);
    prob_corruption = atof(argv[4]);
    if((prob_loss < 0 && prob_loss > 1) || (prob_corruption < 0 && prob_corruption > 1))
    {
        fprintf(stderr, "The probabilities must be in between 0 and 1!\n");
        return 1;
    }
    portno = atoi(argv[1]);

    setup_and_run_server(portno, window_size, prob_loss, prob_corruption);
    return 0; /* Should never get here */
}
