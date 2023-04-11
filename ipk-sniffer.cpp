/**
 * @file ipk-sniffer.c
 * @author Rene Ceska (xceska06@fit.vutbr.cz)
 * @brief
 * @version 0.1.0
 * @date 2023-03-20
 *
 */

#ifdef __linux__ // linux header files

#include <arpa/inet.h>
#include <ctime>
#include <netdb.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#elif _WIN32 // windows header files

#include <Windows.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

#define bzero(b, len) (memset((b), '\0', (len)), (void)0)
#define bcopy(b1, b2, len) (memmove((b2), (b1), (len)), (void)0)

#endif

#define ETHERNET_HEADER_LENGHT 14

// GLOBAl TYPE FOR INTERRUPT HANDLER --------------------
/**
 * @brief stores variables for interrupt handler
 *
 */
typedef struct interruptVarriables_t {
  int client_socket;
  bool connected;
  bool interrupted;
} interruptVarriablesT;

interruptVarriablesT intVals;
//-------------------------------------------------------

/**
 * @brief struct for storing arguments from command line for clients
 *
 */
typedef struct args_t {
  char *host;
  int port;
  bool mode; // false = udp, true = tcp
  bool help;
  bool err;
} argsT;

// FUNCTION DECLARATIONS
argsT parseArgs(int argc, const char *argv[]);
void printHelp(void);

/**
 * @brief parses arguments for client
 *
 * @param argc
 * @param argv
 * @return args
 */
argsT parseArgs(int argc, const char *argv[]) {

  // initialize args
  argsT args;
  args.err = false;
  args.help = false;
  args.mode = 0;
  args.port = 0;
  args.host = (char *)malloc(sizeof(char) * 1000);

  // check if there is right number of arguments
  if (argc != 7 && argc != 2) {
    args.err = true;
    return args;
  }
  // main loop for parsing arguments
  for (int i = 0; i < argc; i++) {
    if (strcmp(argv[i], "-h") == 0) {
      // check if there is value for host and if it is not too long
      if (i + 1 >= argc || strlen(argv[i + 1]) > 1000) {
        args.err = true;
        return args;
      }
      strcpy(args.host, argv[i + 1]);
    }
    if (strcmp(argv[i], "-p") == 0) {
      // check if there is value for port and if it is in range
      if (i + 1 >= argc || atoi(argv[i + 1]) <= 0 ||
          atoi(argv[i + 1]) > 65535) {
        args.err = true;
        return args;
      }
      args.port = atoi(argv[i + 1]);
    }
    if (strcmp(argv[i], "-m") == 0) {
      // check if there is value for mode and if it is valid value
      if (i + 1 >= argc || (strcmp(argv[i + 1], "tcp") != 0 &&
                            strcmp(argv[i + 1], "udp") != 0)) {
        args.err = true;
        return args;
      }
      // set mode
      if (strcmp(argv[i + 1], "tcp") == 0)
        args.mode = 1;
      else
        args.mode = 0;
    }
    if (strcmp(argv[i], "--help") == 0) {
      args.help = true;
    }
  }
  return args;
}

#ifdef __linux__ // linux

/**
 * @brief Get the Server Address object
 *
 * @param server_hostname
 * @param port
 * @return struct sockaddr_in
 */
struct sockaddr_in getServerAddress(const char *server_hostname, int port) {
  struct hostent *server;
  struct sockaddr_in server_address;
  // gets server address by hostname
  if ((server = gethostbyname(server_hostname)) == NULL) {
    fprintf(stderr, "ERR: no such host as %s\n", server_hostname);
    exit(EXIT_FAILURE);
  }

  bzero((char *)&server_address, sizeof(server_address));
  server_address.sin_family = AF_INET;
  bcopy((char *)server->h_addr, (char *)&server_address.sin_addr.s_addr,
        server->h_length);
  server_address.sin_port = htons(port);
  return server_address;
}

#elif _WIN32 // windows

/**
 * @brief Get the Server Address object
 *
 * @param server ipv4 address
 * @param port
 * @return struct sockaddr_in
 */
struct sockaddr_in getServerAddress(const char *server_hostname, int port) {
  struct sockaddr_in server_address;
  server_address.sin_family = AF_INET;
  server_address.sin_port = htons(port);
  if (inet_pton(AF_INET, server_hostname, &(server_address.sin_addr)) <= 0) {
    printf("Error");
    exit(-1);
  }
  return server_address;
}

#endif

/**
 * @brief prints help
 *
 */
void printHelp() {
  printf(" __   __     ______     ______   __     __     ______     ______     "
         "__  __\n"
         "/\\ \"-.\\ \\   /\\  ___\\   /\\__  _\\ /\\ \\  _ \\ \\   /\\  __ \\ "
         "  /\\  == \\   /\\ \\/ /\n"
         "\\ \\ \\-.  \\  \\ \\  __\\   \\/_/\\ \\/ \\ \\ \\/ \".\\ \\  \\ \\ "
         "\\/\\ \\  \\ \\  __<   \\ \\  _\"-.\n"
         " \\ \\_\\\\\"\\_\\  \\ \\_____\\    \\ \\_\\  \\ \\__/\".~\\_\\  \\ "
         "\\_____\\  \\ \\_\\ \\_\\  \\ \\_\\ \\_\\\n"
         "  \\/_/ \\/_/   \\/_____/     \\/_/   \\/_/   \\/_/   \\/_____/   "
         "\\/_/ /_/   \\/_/\\/_/\n"
         "\n"
         "       ______     __   __     __     ______   ______   ______     "
         "______\n"
         "      /\\  ___\\   /\\ \"-.\\ \\   /\\ \\   /\\  ___\\ /\\  ___\\ "
         "/\\  ___\\   /\\  == \\\n"
         "      \\ \\___  \\  \\ \\ \\-.  \\  \\ \\ \\  \\ \\  __\\ \\ \\  "
         "__\\ \\ \\  __\\   \\ \\  __<\n"
         "       \\/\\_____\\  \\ \\_\\\\\"\\_\\  \\ \\_\\  \\ \\_\\    \\ "
         "\\_\\    \\ \\_____\\  \\ \\_\\ \\_\\\n"
         "        \\/_____/   \\/_/ \\/_/   \\/_/   \\/_/     \\/_/     "
         "\\/_____/   \\/_/ /_/\n");
  printf("client for the IPK Calculator Protocol\n\n");
  printf("Usage: ipkcpc -h <host> -p <port> -m <mode>\n\n");
#ifdef __linux__
  printf("  -h <host>   IPv4 address or hostname of the server\n");
#elif _WIN32
  printf("  -h <host>   IPv4 address of the server\n");
#endif
  printf("  -p <port>   port of the server\n");
  printf("  -m <mode>   tcp or udp\n");
  printf(" --help   print this help\n");
  printf("\n\n");
  printf("Example: ipkcpc -h 1.2.3.4 -p 2023 -m udp\n");
}
// TPDO:rewrite
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {

}

void *format_timestamp(struct timeval ts,char* timestmp) {
  struct tm *ltime;
  char timestr[50];
  ltime = localtime(&ts.tv_sec);
  strftime(timestr, sizeof timestr, "%FT%T%z", ltime);
  sprintf(timestmp, "%s.%06ld", timestr, ts.tv_usec);
}

// void print_tcp_packet(const u_char *packet, struct pcap_pkthdr packet_header)
// {
//     struct iphdr *ip = (struct iphdr*)(packet + sizeof(struct ethhdr));
//     struct tcphdr *tcp = (struct tcphdr*)(packet + ip->ihl*4 + sizeof(struct
//     ethhdr));

// }

void print_active_ndevices() {

  pcap_if_t *device;
  char error_buffer[PCAP_ERRBUF_SIZE];

  /* Find a device */
  pcap_findalldevs(&device, error_buffer);
  if (device == NULL) {
    printf("Error finding device: %s\n", error_buffer);
    exit(1);
  }
  printf("Available network devices:\n");
  while (device->next != NULL) {
    printf("%s  - %s\n", device->name, device->description);
    device = device->next;
  }
}

void print_packet_data(const u_char *packet,
                       const struct pcap_pkthdr *packet_header) {
  // print payload
  for (int i = 0; i < packet_header->len; i++) {
    // print new line every 16 bytes
    if (i % 16 == 0) {
      // print ascii representation
      fprintf(stdout, "\t");
      for (int j = i - 16; j < i  && i != 0; j++) {

        if (j == i-8  && i != 0){
            fprintf(stdout, " ");
        }
                // is printable
        if (packet[j] >= 32 && packet[j] <= 128) {
          fprintf(stdout, "%c", packet[j]);
        } else {
          fprintf(stdout, ".");
        }
      }
      fprintf(stdout, "\n0x%04x:\t", i);
    }
    fprintf(stdout, "%02x ", packet[i]);
  }
  fprintf(stdout, "\n");
}
void print_ipv4_packet(const u_char *packet,
                       const struct pcap_pkthdr *packet_header) {

  struct ether_header *eth_header;
  eth_header = (struct ether_header *)packet_header;
  char timestamp[50];
  format_timestamp(packet_header->ts, timestamp);
  fprintf(stdout, "timestamp: %s\n", timestamp);
  fprintf(stdout, "src MAC: %s\n",
          ether_ntoa((const struct ether_addr *)&eth_header->ether_shost));
  fprintf(stdout, "dst MAC: %s \n",
          ether_ntoa((const struct ether_addr *)&eth_header->ether_dhost));
  fprintf(stdout, "frame length: %d\n", packet_header->len);

  const u_char *ip_header;
  const u_char *tcp_header;
  const u_char *payload;

  int ip_header_length;

  // ip header is after ethernet header
  ip_header = packet + ETHERNET_HEADER_LENGHT;
  // its lenght is in the first 4 bits of the first byte
  ip_header_length = ((*ip_header) & 0x0F);
  // convert to number of bytes
  ip_header_length = ip_header_length * 4;

  // get src and dst ip address by adding 12 and 16 to the ip header
  fprintf(stdout, "src IP: %s\n",
          inet_ntoa(*(struct in_addr *)(ip_header + 12)));
  fprintf(stdout, "dst IP: %s\n",
          inet_ntoa(*(struct in_addr *)(ip_header + 16)));
  // get protocol number
  u_char protocol = *(ip_header + 9);

  switch (protocol) {
  case IPPROTO_TCP:
  printf("TCP\n");
    fprintf(stdout, "src port: %d\n",
            ntohs(*(u_short *)(ip_header + ip_header_length)));
    fprintf(stdout, "dst port: %d\n",
            ntohs(*(u_short *)(ip_header + ip_header_length + 2)));

   // print_packet_data(packet, packet_header);

    break;
  case IPPROTO_UDP:
  printf("UDP\n");
    fprintf(stdout, "src port: %d\n",
            ntohs(*(u_short *)(ip_header + ip_header_length)));
    fprintf(stdout, "dst port: %d\n",
            ntohs(*(u_short *)(ip_header + ip_header_length + 2)));
    break;
  case IPPROTO_ICMP:
  printf("ICMP\n");
    fprintf(stdout, "dst port: %d\n",
            ntohs(*(u_short *)(ip_header + ip_header_length)));
    fprintf(stdout, "src port: %d\n",
            ntohs(*(u_short *)(ip_header + ip_header_length + 2)));
    break;
  case IPPROTO_ICMPV6:
  printf("ICMPv6\n");
    fprintf(stdout, "dst port: %d\n",
            ntohs(*(u_short *)(ip_header + ip_header_length)));
    fprintf(stdout, "src port: %d\n",
            ntohs(*(u_short *)(ip_header + ip_header_length + 2)));
    break;
  default:
    fprintf(stdout, "protocol: unknown\n");
    break;
  }
  print_packet_data(packet, packet_header);
}

// TPDO:rewrite
void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header,
                       const u_char *packet_body) {

  struct ether_header *eth_header;
  /* The packet is larger than the ether_header struct,
     but we just want to look at the first part of the packet
     that contains the header. We force the compiler
     to treat the pointer to the packet as just a pointer
     to the ether_header. The data payload of the packet comes
     after the headers. Different packet types have different header
     lengths though, but the ethernet header is always the same (14 bytes) */
  eth_header = (struct ether_header *)packet_body;

  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
    print_ipv4_packet(packet_body, packet_header);
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
    printf("ARP\n");
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
    printf("Reverse IPV6\n");
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP) {
    printf("Reverse reverse arp\n");
  }

  // //printf("Packet captured");
  // //print_packet_info(packet_body, *packet_header);
  // printf("timestamp: %s\n", format_timestamp(packet_header->ts));
  // printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", packet_body[6],
  // packet_body[7], packet_body[8], packet_body[9], packet_body[10],
  // packet_body[11]); printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
  // packet_body[0], packet_body[1], packet_body[2], packet_body[3],
  // packet_body[4], packet_body[5]); printf("frame lenght: %d\n",
  // packet_header->len); printf("src IP: %d.%d.%d.%d\n", packet_body[26],
  // packet_body[27], packet_body[28], packet_body[29]); printf("dst IP:
  // %d.%d.%d.%d\n", packet_body[30], packet_body[31], packet_body[32],
  // packet_body[33]); printf("src port: %d\n", packet_body[34] * 256 +
  // packet_body[35]); printf("dst port: %d\n", packet_body[36] * 256 +
  // packet_body[37]); printf("\n");
  // //print data
  // int i;
  // for (i = 0; i < packet_header->len; i++) {
  //     printf("%02x ", packet_body[i]);
  //     if ((i + 1) % 16 == 0) {
  //         printf("\n");
  //     }
  // }
  // return;
}

int main(int argc, const char *argv[]) {

  printHelp();
  print_active_ndevices();
  // pcap_if_t *device; /* Name of device (e.g. eth0, wlan0) */
  // char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */

  /* Find a device */
  // pcap_findalldevs(&device, error_buffer);
  // if (device == NULL) {
  //     printf("Error finding device: %s\n", error_buffer);
  //     return 1;
  // }

  // while (device->next != NULL) {
  //     device = device->next;
  //     printf("Network device found: %s\n", device->name);
  // }

  char error_buffer[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_create("wlan0", error_buffer);
  printf("%d\n",
         pcap_set_promisc(handle, 1)); /* Capture packets that are not yours */
  printf("%d\n", pcap_set_snaplen(handle, 2048)); /* Snapshot length */
  printf("%d\n", pcap_set_timeout(handle, 100));  /* Timeout in milliseconds */
  printf("%d\n", pcap_activate(handle));

  /* Snapshot length is how many bytes to capture from each packet. This
   * includes*/
  int snapshot_length = 2048;
  /* End the loop after this many packets are captured */
  u_char *my_arguments = NULL;
  printf("%d", pcap_datalink(handle));
  printf("%d", pcap_loop(handle, 1000, my_packet_handler, my_arguments));
  /* handle is ready for use with pcap_next() or pcap_loop() */
  printf("%s", error_buffer);
  pcap_close(handle);
  return 0;
}