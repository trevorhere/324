#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

typedef unsigned int dns_rr_ttl;
typedef unsigned short dns_rr_type;
typedef unsigned short dns_rr_class;
typedef unsigned short dns_rdata_len;
typedef unsigned short dns_rr_count;
typedef unsigned short dns_query_id;
typedef unsigned short dns_flags;

typedef struct
{
  char *name;
  dns_rr_type type;
  dns_rr_class class;
  dns_rr_ttl ttl;
  dns_rdata_len rdata_len;
  unsigned char *rdata;
} dns_rr;

struct dns_answer_entry;
struct dns_answer_entry
{
  char *value;
  struct dns_answer_entry *next;
};
typedef struct dns_answer_entry dns_answer_entry;
char *ip_str;
char *ip_copy;

void print_wire(unsigned char *wire, int len)
{

  for (int i = 0; i < len; i++)
  {
    printf(" %x ", wire[i]);
  }
  printf("\n");
}

void free_answer_entries(dns_answer_entry *ans)
{
  dns_answer_entry *next;
  while (ans != NULL)
  {
    next = ans->next;
    free(ans->value);
    free(ans);
    ans = next;
  }
}

void print_bytes(unsigned char *bytes, int byteslen)
{
  int i, j, byteslen_adjusted;
  unsigned char c;

  if (byteslen % 8)
  {
    byteslen_adjusted = ((byteslen / 8) + 1) * 8;
  }
  else
  {
    byteslen_adjusted = byteslen;
  }
  for (i = 0; i < byteslen_adjusted + 1; i++)
  {
    if (!(i % 8))
    {
      if (i > 0)
      {
        for (j = i - 8; j < i; j++)
        {
          if (j >= byteslen_adjusted)
          {
            printf("  ");
          }
          else if (j >= byteslen)
          {
            printf("  ");
          }
          else if (bytes[j] >= '!' && bytes[j] <= '~')
          {
            printf(" %c", bytes[j]);
          }
          else
          {
            printf(" .");
          }
        }
      }
      if (i < byteslen_adjusted)
      {
        printf("\n%02X: ", i);
      }
    }
    else if (!(i % 4))
    {
      printf(" ");
    }
    if (i >= byteslen_adjusted)
    {
      continue;
    }
    else if (i >= byteslen)
    {
      printf("   ");
    }
    else
    {
      printf("%02X ", bytes[i]);
    }
  }
  printf("\n");
}

void canonicalize_name(char *name)
{
  /*
	 * Canonicalize name in place.  Change all upper-case characters to
	 * lower case and remove the trailing dot if there is any.  If the name
	 * passed is a single dot, "." (representing the root zone), then it
	 * should stay the same.
	 *
	 * INPUT:  name: the domain name that should be canonicalized in place
	 */

  int namelen, i;

  // leave the root zone alone
  if (strcmp(name, ".") == 0)
  {
    return;
  }

  namelen = strlen(name);
  // remove the trailing dot, if any
  if (name[namelen - 1] == '.')
  {
    name[namelen - 1] = '\0';
  }

  // make all upper-case letters lower case
  for (i = 0; i < namelen; i++)
  {
    if (name[i] >= 'A' && name[i] <= 'Z')
    {
      name[i] += 32;
    }
  }
}

int name_ascii_to_wire(char *name, unsigned char *wire)
{
  /*
	 * Convert a DNS name from string representation (dot-separated labels)
	 * to DNS wire format, using the provided byte array (wire).  Return
	 * the number of bytes used by the name in wire format.
	 *
	 * INPUT:  name: the string containing the domain name
	 * INPUT:  wire: a pointer to the array of bytes where the
	 *              wire-formatted name should be constructed
	 * OUTPUT: the length of the wire-formatted name.
	 */

  int name_length = strlen(name);
  int count = 0;
  int prev_period = 0;
  int current_char = 1;
  int wire_iterator = 1;

  for (int i = 0; i < name_length; i++)
  {
    if (name[i] == '.')
    {
      wire[prev_period] = (char)count;
      //  printf("cc: %x\n", (char) count);
      prev_period = (prev_period + count) + 1;
      count = 0;
      //print_wire(wire, (int) stlen((char *) wire));
    }
    else
    {

      count++;
      wire[wire_iterator] = name[i];
      //print_wire(wire, (int) stlen((char *) wire));
    }
    wire_iterator++;
  }

  //print_wire(wire, (int) stlen((char *) wire));
  wire[prev_period] = count;
  wire[wire_iterator] = (char)0;
  wire_iterator++;
  return wire_iterator;
}

char *name_ascii_from_wire(unsigned char *wire, int *indexp)
{
  /*
	 * Extract the wire-formatted DNS name at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return its string
	 * representation (dot-separated labels) in a char array allocated for
	 * that purpose.  Update the value pointed to by indexp to the next
	 * value beyond the name.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp, a pointer to the index in the wire where the
	 *              wire-formatted name begins
	 * OUTPUT: a string containing the string representation of the name,
	 *              allocated on the heap.
	 */

  int compression_ptr = 0; // 1
  int index = 0;
  int wire_len = 0;
  unsigned char string_builder[1024];

  if ((unsigned char)wire[*indexp] == 0xc0)
  {
    index = *indexp;
    *indexp = wire[*indexp + 1];
  }

  while (wire[*indexp] != '\0')
  {
    // handle compression
    if (wire[*indexp] == 0xc0)
    {
      compression_ptr = *indexp;
      *indexp = wire[*indexp + 1];
    }
    int curr_len = wire[*indexp];
    *indexp += 1;
    memcpy(string_builder + wire_len, wire + *indexp, curr_len);
    // print_wire(string_builder, (int) strlen((char *) string_builder));
    *indexp += curr_len;
    wire_len += curr_len;
    string_builder[wire_len++] = '.';
  }
  *indexp += 1;

  unsigned char *name = malloc(wire_len * sizeof(char));
  string_builder[wire_len - 1] = '\0';
  memcpy(name, string_builder, wire_len);
  // print_wire(name, (int) strlen((char *) name));

  //  if (index){
  //     *indexp
  //  }

  if (index)
  {
    *indexp = index + 2;
  }
  // print_wire(name, (int) strlen((char *) name));
  return name;
}
uint32_t c_long(uint32_t x)
{
  // printf("long before: %d\n", &x);
  // printf("long after: %d\n", ntohl(x));
  return ntohl(x);
}
uint16_t c_short(uint16_t x)
{
  // printf("short before: %d\n", x);
  // printf("short after: %d\n", ntohs(x));
  return ntohs(x);
}

dns_rr rr_from_wire(unsigned char *wire, int *indexp, int query_only)
{
  /*
	 * Extract the wire-formatted resource record at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return a
	 * dns_rr (struct) populated with its contents. Update the value
	 * pointed to by indexp to the next value beyond the resource record.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp: a pointer to the index in the wire where the
	 *              wire-formatted resource record begins
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
	 *              we are extracting a full resource record or only a
	 *              query (i.e., in the question section of the DNS
	 *              message).  In the case of the latter, the ttl,
	 *              rdata_len, and rdata are skipped.
	 * OUTPUT: the resource record (struct)
	 */

  dns_rr rr_struct;
  // typedef struct {
  // 	char *name;
  rr_struct.name = name_ascii_from_wire(wire, indexp);
  // 	dns_rr_type type;
  memcpy(&rr_struct.type, wire + *indexp, sizeof(dns_rr_type));
  rr_struct.type = c_short(rr_struct.type);
  *indexp += sizeof(dns_rr_type);
  // 	dns_rr_class class;
  memcpy(&rr_struct.class, wire + *indexp, sizeof(dns_rr_class));
  rr_struct.class = c_short(rr_struct.class);
  *indexp += sizeof(dns_rr_class);

  if (query_only != 1)
  {
    //		 printf("query_only: %d\n", query_only);
    // 	dns_rr_ttl ttl;  ---> int, rest are short
    memcpy(&rr_struct.ttl, wire + *indexp, sizeof(dns_rr_ttl));
    rr_struct.ttl = c_long(rr_struct.ttl);
    *indexp += sizeof(dns_rr_ttl);
    // 	dns_rdata_len rdata_len;
    memcpy(&rr_struct.rdata_len, wire + *indexp, sizeof(dns_rdata_len));
    rr_struct.rdata_len = c_short(rr_struct.rdata_len);
    *indexp += sizeof(dns_rdata_len);
    // 	unsigned char *rdata;
    rr_struct.rdata = malloc(500 * sizeof(char));
    memcpy(rr_struct.rdata, wire + *indexp, rr_struct.rdata_len);
    *indexp += rr_struct.rdata_len;
    // } dns_rr;
  }
  else
  {
    // printf("query_only: %d\n", query_only);
    ;
  }

  return rr_struct;
}

unsigned short create_dns_query(char *qname, dns_rr_type qtype, unsigned char *wire)
{
  /*
	 * Create a wire-formatted DNS (query) message using the provided byte
	 * array (wire).  Create the header and question sections, including
	 * the qname and qtype.
	 *
	 * INPUT:  qname: the string containing the name to be queried
	 * INPUT:  qtype: the integer representation of type of the query (type A == 1)
	 * INPUT:  wire: the pointer to the array of bytes where the DNS wire
	 *               message should be constructed
	 * OUTPUT: the length of the DNS wire message
	 */

  // 	 unsigned char msg[] = {
  // 0x27, 0xd6,

  //  0x01, 0x00,
  // 0x00, 0x01, 0x00, 0x00,
  // 0x00, 0x00, 0x00, 0x00,
  // 0x03, 0x77, 0x77, 0x77,
  // 0x07, 0x65, 0x78, 0x61,
  // 0x6d, 0x70, 0x6c, 0x65,
  // 0x03, 0x63, 0x6f, 0x6d,
  // 0x00, 0x00, 0x01, 0x00,
  // 0x01
  // };

  memset(wire, 0, 1024);
  const int wire_start_len = 12;
  const int wire_end_len = 4;
  unsigned char wire_start_temp[12 /* wire_start_len*/] = {
      0x00, 0x00, 0x01, 0x00,
      0x00, 0x01, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00};

  unsigned char wire_end_temp[4 /*wire_end_len*/] = {
      0x00, 0x01, 0x00, 0x01};

  wire_start_temp[0] = rand() % 0xff; // random
  wire_start_temp[1] = rand() % 0xff; // random

  memcpy(wire, wire_start_temp, wire_start_len);
  //  print_bytes(wire, 32);

  unsigned char res_wire[1024];
  int wire_len = name_ascii_to_wire(qname, res_wire);
  memcpy(wire + wire_start_len, res_wire, wire_len);
  //  print_bytes(wire, 32);

  // if(*qname == '.'){
  //  // maybe come back to this, bigger problems to solve elsewhere...
  // 	unsigned char * final = wire + wire_start_len + wire_len;
  // 	return wire_start_len + wire_len;
  // }

  unsigned char *final = wire + wire_start_len + wire_len;
  memcpy(final, wire_end_temp, wire_end_len);
  //	print_wire(final, (int) strlen((char *) final));

  return wire_start_len + wire_len + wire_end_len;
}

dns_answer_entry *get_answer_address(char *qname, dns_rr_type qtype, unsigned char *wire)
{
  /*
	 * Extract the IPv4 address from the answer section, following any
	 * aliases that might be found, and return the string representation of
	 * the IP address.  If no address is found, then return NULL.
	 *
	 * INPUT:  qname: the string containing the name that was queried
	 * INPUT:  qtype: the integer representation of type of the query (type A == 1)
	 * INPUT:  wire: the pointer to the array of bytes representing the DNS wire message
	 * OUTPUT: a linked list of dns_answer_entrys the value member of each
	 * reflecting either the name or IP address.  If
	 */
  dns_answer_entry *head = NULL;
  short num_questions;
  short num_answers = wire[6] << 8 | wire[7];

  int offset = 4; // 8;
  int sh_o = sizeof(short);
  int dae_o = sizeof(dns_answer_entry);

  memcpy(&num_questions, wire + offset, sh_o);
  // print_bytes(wire, 32);

  num_questions = ntohs(num_questions);

  for (int i = 0; i < num_questions; i++)
  {
    int off2 = offset;
    offset += 8;
    rr_from_wire(wire, &offset, 1);
    // wire <- question
  }

  for (int i = 0; i < num_answers; i++)
  {
    dns_rr record = rr_from_wire(wire, &offset, 0);
    dns_answer_entry *curr; // = NULL;
    if (record.type == 0x01)
    {
      // get IP
      ip_str = malloc(16);
      ip_copy = ip_str;
      // memset(ip_str, 0, 16);

      sprintf(ip_copy, "%d.%d.%d.%d", record.rdata[0], record.rdata[1], record.rdata[2], record.rdata[3]);

      if (head == NULL)
      {
        head = malloc(dae_o);
        curr = head;
        //	free(head);
      }
      else
      {
        curr->next = malloc(dae_o);
        curr = curr->next;
        //	free(curr->next);
      }
      curr->value = ip_copy;
    }
    else if (record.type == 0x5)
    {
      // get CNAME
      int i = offset - record.rdata_len;
      char *wire_res = name_ascii_from_wire(wire, &i);
      //		print_bytes(wire_res, 32);

      if (head == NULL)
      {
        head = malloc(dae_o);
        curr = head;
      }
      else
      {
        curr->next = malloc(dae_o);
        curr = curr->next;
      }
      curr->value = wire_res;
    }
  }

  //
  return head;
}

int send_recv_message(unsigned char *request, int requestlen, unsigned char *response, char *server, unsigned short port)
{
  /*
	 * Send a message (request) over UDP to a server (server) and port
	 * (port) and wait for a response, which is placed in another byte
	 * array (response).  Create a socket, "connect()" it to the
	 * appropriate destination, and then use send() and recv();
	 *
	 * INPUT:  request: a pointer to an array of bytes that should be sent
	 * INPUT:  requestlen: the length of request, in bytes.
	 * INPUT:  response: a pointer to an array of bytes in which the
	 *             response should be received
	 * OUTPUT: the size (bytes) of the response received
	 */
  struct sockaddr_in addr;
  //  socklen_t peer_addr_len;
  int sfd, r;
  unsigned char buf[1024];
  // char buf[BUF_SIZE];

  memset((char *)&addr, 0, sizeof(addr));
  //	memset(&hints, 0, sizeof(struct addrinfo));

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(server);
  addr.sin_port = htons(port);

  // 		struct addrinfo hints;
  // struct addrinfo *result, *rp;
  // int sfd, s;
  // struct sockaddr_storage peer_addr;
  // ssize_t nread;

  sfd = socket(PF_INET, SOCK_DGRAM, 0);

  connect(sfd, (struct sockaddr *)&addr, sizeof(addr));
  //connect(sfd, rp->ai_addr, rp->ai_addrlen)

  send(sfd, request, requestlen, 0);
  r = recv(sfd, buf, 1024, 0);
  //    recv(csfd, bxf, BIG_BUFF, 0){

  memcpy(response, buf, r);
  //	print_wire(response, strlen(response));

  return r;
}

dns_answer_entry *resolve(char *qname, char *server, char *port)
{

  // printf("qname: %s\n", qname);
  unsigned char req[1024];
  unsigned char res[1024];

  unsigned short req_len = create_dns_query(qname, (dns_rr_type)1, req);
  send_recv_message(req, req_len, res, server, (unsigned short)strtoul(port, NULL, 0));

  return get_answer_address(qname, (dns_rr_type)1, res);
}

int main(int argc, char *argv[])
{
  char *port;
  dns_answer_entry *ans_list, *ans;
  if (argc < 3)
  {
    fprintf(stderr, "Usage: %s <domain name> <server> [ <port> ]\n", argv[0]);
    exit(1);
  }
  if (argc > 3)
  {
    port = argv[3];
  }
  else
  {
    port = "53";
  }
  ans = ans_list = resolve(argv[1], argv[2], port);
  while (ans != NULL)
  {
    printf("%s\n", ans->value);
    ans = ans->next;
  }
  if (ans_list != NULL)
  {
    free_answer_entries(ans_list);
  }
}