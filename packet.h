#define MAX_NAME_LEN 128
#define MAX_PACKET_SIZE 1024

enum packet_type_t
{
	DATA,
	ACK,
	FINACK,
	ERROR
};

typedef struct packet
{
	enum packet_type_t type;

	int seq_num;
	int ack_num;
	int fin;

	int payload_length;
	char name[MAX_NAME_LEN];
	char payload[MAX_PACKET_SIZE];
} packet_t;