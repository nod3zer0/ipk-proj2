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
  char *interface;
  bool port;
  bool tcp;
  bool udp;
  bool arp;
  bool icmp4;
  bool icmp6;
  bool help;
  int num;
  bool err;
  bool NDP;
  bool IGMP;
  bool MLD;
} argsT;

typedef struct {
  int id;
  char value[255];
} Configuration;

typedef struct packet_data_t {
  char timestamp[100];
  char source_mac[1000];
  char destination_mac[1000];
  char source_ip[1000];
  char destination_ip[1000];
  char protocol[1000];
  bool NDP;
  bool IGMP;
  bool MLD;
  uint16_t source_port;
  uint16_t destination_port;
} packetDataT;

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
  args.port = false;
  args.tcp = false;
  args.udp = false;
  args.arp = false;
  args.icmp4 = false;
  args.icmp6 = false;
  args.num = 0;
  args.IGMP = false;
  args.MLD = false;
  args.NDP = false;
  args.interface = (char *)malloc(sizeof(char) * 1000);

  // main loop for parsing arguments
  for (int i = 0; i < argc; i++) {
    if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0) {
      // check if there is value for host and if it is not too long

      if (i + 1 >= argc) {
        strcpy(args.interface, "");
        return args;
      } else {
        if (strlen(argv[i + 1]) > 1000) {
          args.err = true;
          return args;
        }
        strcpy(args.interface, argv[i + 1]);
      }
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
    if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--tcp") == 0) {
      args.tcp = true;
    }
    if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--udp") == 0) {
      args.udp = true;
    }
    if (strcmp(argv[i], "--arp") == 0) {
      args.arp = true;
    }
    if (strcmp(argv[i], "--icmp4") == 0) {
      args.icmp4 = true;
    }
    if (strcmp(argv[i], "--icmp6") == 0) {
      args.icmp6 = true;
    }
    if (strcmp(argv[i], "--ndp") == 0) {
      args.NDP = true;
    }
    if (strcmp(argv[i], "--igmp") == 0) {
      args.IGMP = true;
    }
    if (strcmp(argv[i], "--mld") == 0) {
      args.MLD = true;
    }
    if (strcmp(argv[i], "-n") == 0) {
      if (i + 1 >= argc || atoi(argv[i + 1]) <= 0) {
        args.err = true;
        return args;
      }
      args.num = atoi(argv[i + 1]);
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

void *format_timestamp(struct timeval ts, char *timestmp) {
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
      for (int j = i - 16; j < i && i != 0; j++) {

        if (j == i - 8 && i != 0) {
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

void get_ipv4_packet_info(const u_char *packet,
                          const struct pcap_pkthdr *packet_header,
                          packet_data_t *packet_data) {

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

  inet_ntop(AF_INET, (struct in_addr *)(ip_header + 12), packet_data->source_ip,
            INET_ADDRSTRLEN);
  inet_ntop(AF_INET, (struct in_addr *)(ip_header + 16),
            packet_data->destination_ip, INET_ADDRSTRLEN);

  u_char protocol = *(ip_header + 9);

  switch (protocol) {
  case IPPROTO_TCP:
    strcpy(packet_data->protocol, "TCP");
    packet_data->source_port =
        ntohs(*(u_short *)(ip_header + ip_header_length));
    packet_data->destination_port =
        ntohs(*(u_short *)(ip_header + ip_header_length + 2));

    break;
  case IPPROTO_UDP:
    strcpy(packet_data->protocol, "UDP");
    packet_data->source_port =
        ntohs(*(u_short *)(ip_header + ip_header_length));
    packet_data->destination_port =
        ntohs(*(u_short *)(ip_header + ip_header_length + 2));
    break;
  case IPPROTO_ICMP:
    strcpy(packet_data->protocol, "ICMP4");
    break;
  case IPPROTO_IGMP:
    packet_data->IGMP = true;
    break;
  }
  // print_packet_data(packet, packet_header);
  // printf("\n\n")
}

void get_ipv6_packet_info(const u_char *packet,
                          const struct pcap_pkthdr *packet_header,
                          packet_data_t *packet_data) {

  const u_char *ip_header;
  const u_char *tcp_header;
  const u_char *payload;

  int ip_header_length;

  // ip header is after ethernet header
  ip_header = packet + ETHERNET_HEADER_LENGHT;
  // its lenght is in the first 4 bits of the first byte
  ip_header_length = ((*ip_header) & 0x0F);
  // convert to number of bytes
  ip_header_length = 40;

  inet_ntop(AF_INET6, (struct in6_addr *)(ip_header + 8),
            packet_data->source_ip, INET6_ADDRSTRLEN);
  inet_ntop(AF_INET6, (struct in6_addr *)(ip_header + 24),
            packet_data->destination_ip, INET6_ADDRSTRLEN);

  u_char protocol = *(ip_header + 6);

  switch (protocol) {
  case IPPROTO_TCP:
    strcpy(packet_data->protocol, "TCP");
    packet_data->source_port =
        ntohs(*(u_short *)(ip_header + ip_header_length));
    packet_data->destination_port =
        ntohs(*(u_short *)(ip_header + ip_header_length + 2));

    break;
  case IPPROTO_UDP:
    strcpy(packet_data->protocol, "UDP");
    packet_data->source_port =
        ntohs(*(u_short *)(ip_header + ip_header_length));
    packet_data->destination_port =
        ntohs(*(u_short *)(ip_header + ip_header_length + 2));

    break;
  case IPPROTO_ICMPV6:
    strcpy(packet_data->protocol, "ICMP6");

    u_char type = *(ip_header + ip_header_length);
    if (type == 133 || type == 134 || type == 135 || type == 136 ||
        type == 137) {
      packet_data->NDP = true;
    } else if (type == 130 || type == 131 || type == 132) {
      packet_data->MLD = true;
    }
    break;
  }
}

void get_arp_packet_info(const u_char *packet,
                         const struct pcap_pkthdr *packet_header,
                         packet_data_t *packet_data) {

  const u_char *arp_header;
  const u_char *tcp_header;
  const u_char *payload;

  arp_header = packet + ETHERNET_HEADER_LENGHT;

  if (*(arp_header + 2) == 0x08) {
    printf("IPV4_______________________");
    inet_ntop(AF_INET, (struct in_addr *)(arp_header + 8),
              packet_data->source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, (struct in_addr *)(arp_header + 14),
              packet_data->destination_ip, INET_ADDRSTRLEN);

  } else if (*(arp_header + 2) == 0x86 && *(arp_header + 4) == 0xdd) {
    printf("IPV6_______________________");
    inet_ntop(AF_INET6, (struct in6_addr *)(arp_header + 8),
              packet_data->source_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, (struct in6_addr *)(arp_header + 14),
              packet_data->destination_ip, INET_ADDRSTRLEN);
  }
  // filter ethernet type
  strcpy(packet_data->protocol, "ARP");
}

// TPDO:rewrite
void my_packet_handler(u_char conf[], const struct pcap_pkthdr *packet_header,
                       const u_char *packet_body) {

  struct ether_header *eth_header;
  packet_data_t packet_data;
  packet_data = {
      .timestamp = "",
      .source_mac = "",
      .destination_mac = "",
      .source_ip = "",
      .destination_ip = "",
      .protocol = "",
      .NDP = false,
      .IGMP = false,
      .MLD = false,
      .source_port = 0,
      .destination_port = 0,
  };
  argsT args = *(argsT *)conf;

  eth_header = (struct ether_header *)packet_header;
  char timestamp[50];
  format_timestamp(packet_header->ts, timestamp);
  strcpy(packet_data.timestamp, timestamp);
  strcpy(packet_data.source_mac,
         ether_ntoa((const struct ether_addr *)&eth_header->ether_shost));
  strcpy(packet_data.destination_mac,
         ether_ntoa((const struct ether_addr *)&eth_header->ether_dhost));

  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
    get_ipv4_packet_info(packet_body, packet_header, &packet_data);
    printf("IPV4_______________________");
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
    get_arp_packet_info(packet_body, packet_header, &packet_data);
    printf("ARP_______________________");
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
    get_ipv6_packet_info(packet_body, packet_header, &packet_data);
    printf("IPV6_______________________");
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP) {
    printf("Reverse reverse arp\n");
  } else {
    return;
  }

  if ((args.tcp == 1 && strcmp(packet_data.protocol, "TCP") == 0) ||
      (args.udp == 1 && strcmp(packet_data.protocol, "UDP") == 0) ||
      (args.icmp4 == 1 && strcmp(packet_data.protocol, "ICMP4") == 0 )||
      (args.icmp6 == 1 && strcmp(packet_data.protocol, "ICMP6") == 0 )||
      (args.arp == 1 && strcmp(packet_data.protocol, "ARP") == 0) ||
      (args.IGMP == 1 && packet_data.IGMP == true) ||
      (args.NDP == 1 && packet_data.NDP == true )||
      (args.MLD == 1 && packet_data.MLD == true )||
      (args.tcp == 0 && args.udp == 0 && args.icmp4 == 0 && args.icmp6 == 0 &&
       args.arp == 0 && args.IGMP == 0 && args.NDP == 0 && args.MLD == 0)) {

    if (args.port == 0 || args.port == packet_data.source_port ||
        args.port == packet_data.destination_port) {
      if (strcmp(packet_data.timestamp, "") != 0)
        fprintf(stdout, "timestamp: %s\n", packet_data.timestamp);
      if (strcmp(packet_data.source_mac, "") != 0)
        fprintf(stdout, "src MAC: %s\n", packet_data.source_mac);
      if (strcmp(packet_data.destination_mac, "") != 0)
        fprintf(stdout, "dst MAC: %s\n", packet_data.destination_mac);
      if (strcmp(packet_data.source_ip, "") != 0)
        fprintf(stdout, "src IP: %s\n", packet_data.source_ip);
      if (strcmp(packet_data.destination_ip, "") != 0)
        fprintf(stdout, "dst IP: %s\n", packet_data.destination_ip);
      if (strcmp(packet_data.protocol, "") != 0)
        fprintf(stdout, "protocol: %s\n", packet_data.protocol);
      if (packet_data.source_port != 0)
        fprintf(stdout, "src port: %d\n", packet_data.source_port);
      if (packet_data.destination_port != 0)
        fprintf(stdout, "dst port: %d\n", packet_data.destination_port);
      printf("\n");
      if (packet_body != NULL)
        print_packet_data(packet_body, packet_header);
      printf("\n\n");
    }
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

  argsT args = parseArgs(argc, argv);

  if (args.help) {
    printHelp();
    return 0;
  } else if (args.err) {
    printHelp();
    return 1;
  }
  if (args.interface == "" ||
      (!args.arp && !args.icmp4 && !args.icmp6 && !args.tcp && !args.udp &&
       !args.num && !args.port && args.interface == "")) {
    print_active_ndevices();
    return 0;
  }

  // printHelp();

  char error_buffer[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_create(args.interface, error_buffer);
  printf("%d\n",
         pcap_set_promisc(handle, 1)); /* Capture packets that are not yours */
  printf("%d\n", pcap_set_snaplen(handle, 2048)); /* Snapshot length */
  printf("%d\n", pcap_set_timeout(handle, 100));  /* Timeout in milliseconds */
  printf("%d\n", pcap_activate(handle));

  /* Snapshot length is how many bytes to capture from each packet. This
   * includes*/
  int snapshot_length = 2048;
  /* End the loop after this many packets are captured */
  // u_char *my_arguments = NULL;
  printf("%d", pcap_datalink(handle));

  char port[20] = "";
  printf("%d", pcap_loop(handle, args.num, my_packet_handler, (u_char *)&args));
  /* handle is ready for use with pcap_next() or pcap_loop() */
  printf("%s", error_buffer);
  pcap_close(handle);
  return 0;
}