/**
 * @file ipk-sniffer.c
 * @author Rene Ceska (xceska06@fit.vutbr.cz)
 * @brief
 * @version 1.0.0
 * @date 2023-04-13
 *
 */

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

#define ETHERNET_HEADER_LENGHT 14

/**
 * @brief struct for storing arguments from command line
 *
 */
typedef struct args_t {
  char *interface;
  int port;
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

/**
 * @brief struct for storing packet data
 *
 */
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
  bool icmp6_request_response;
  uint16_t source_port;
  uint16_t destination_port;
} packetDataT;

// GLOBAL VARIABLES FOR INTERRUPT HANDLING
pcap_t *handle;

// FUNCTION DECLARATIONS
argsT parseArgs(int argc, const char *argv[]);
void printHelp(void);
void format_timestamp(struct timeval ts, char *timestamp);
void print_active_ndevices();
void print_packet_data(const u_char *packet,
                       const struct pcap_pkthdr *packet_header);
void get_ipv4_packet_info(const u_char *packet,
                          const struct pcap_pkthdr *packet_header,
                          packet_data_t *packet_data);
void get_ipv6_packet_info(const u_char *packet,
                          const struct pcap_pkthdr *packet_header,
                          packet_data_t *packet_data);
void get_arp_packet_info(const u_char *packet,
                         const struct pcap_pkthdr *packet_header,
                         packet_data_t *packet_data);
int packet_handler(u_char conf[], const struct pcap_pkthdr *packet_header,
                   const u_char *packet_body);

void INThandler(int sig) {
  pcap_close(handle);
  exit(0);
}

/**
 * @brief parses arguments for sniffer
 *
 * @param argc
 * @param argv
 * @return argsT
 */
argsT parseArgs(int argc, const char *argv[]) {

  // initialize args
  argsT args;
  args.err = false;
  args.help = false;
  args.port = 0;
  args.tcp = false;
  args.udp = false;
  args.arp = false;
  args.icmp4 = false;
  args.icmp6 = false;
  args.num = 1;
  args.IGMP = false;
  args.MLD = false;
  args.NDP = false;
  args.interface = (char *)malloc(sizeof(char) * 1000);

  // main loop for parsing arguments
  for (int i = 1; i < argc; i++) {
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
      i++; // skip next argument
      continue;
    }
    if (strcmp(argv[i], "-p") == 0) {
      // check if there is value for port and if it is in range
      if (i + 1 >= argc || atoi(argv[i + 1]) <= 0 ||
          atoi(argv[i + 1]) > 65535) {
        args.err = true;
        return args;
      }
      args.port = atoi(argv[i + 1]);
      i++; // skip next argument
      continue;
    }
    if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--tcp") == 0) {
      args.tcp = true;
      continue;
    }
    if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--udp") == 0) {
      args.udp = true;
      continue;
    }
    if (strcmp(argv[i], "--arp") == 0) {
      args.arp = true;
      continue;
    }
    if (strcmp(argv[i], "--icmp4") == 0) {
      args.icmp4 = true;
      continue;
    }
    if (strcmp(argv[i], "--icmp6") == 0) {
      args.icmp6 = true;
      continue;
    }
    if (strcmp(argv[i], "--ndp") == 0) {
      args.NDP = true;
      continue;
    }
    if (strcmp(argv[i], "--igmp") == 0) {
      args.IGMP = true;
      continue;
    }
    if (strcmp(argv[i], "--mld") == 0) {
      args.MLD = true;
      continue;
    }
    if (strcmp(argv[i], "-n") == 0) {
      if (i + 1 >= argc || atoi(argv[i + 1]) <= 0) {
        args.err = true;
        return args;
      }
      args.num = atoi(argv[i + 1]);
      i++; // skip next argument
      continue;
    }
    if (strcmp(argv[i], "--help") == 0) {
      args.help = true;
      continue;
    }
    // check if there is unknown argument
    fprintf(stderr, "Unknown argument: %s\n", argv[i]);
    args.err = true;
    return args;
  }
  return args;
}

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

  printf("\nNetwork analyzer that is able to capture and filter packets on a "
         "specific network interface.\n\n");
  printf("Usage: ipk-sniffer [-i interface | --interface interface] {-p port "
         "[--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] "
         "{-n num}\n\n");
  printf("Options:\n");
  printf(
      "\t-i eth0 (just one interface to sniff) or --interface. If this "
      "parameter is not specified (and any other parameters as well), or if "
      "only -i/--interface is specified without a value (and any other "
      "parameters are unspecified), a list of active interfaces is printed.\n");
  printf("\t-t or --tcp (will display TCP segments and is optionally "
         "complemented by -p functionality).\n");
  printf("\t-u or --udp (will display UDP datagrams and is optionally "
         "complemented by-p functionality).\n");
  printf(
      "\t-p 23 (extends previous two parameters to filter TCP/UDP based on "
      "port number; if this parameter is not present, then no filtering by "
      "port number occurs; if the parameter is given, the given port can occur "
      "in both the source and destination part of TCP/UDP headers).\n");
  printf("\t--icmp4 (will display only ICMPv4 packets).\n");
  printf("\t--icmp6 (will display only ICMPv6 echo request/response).\n");
  printf("\t--arp (will display only ARP frames).\n");
  printf("\t--ndp (will display only ICMPv6 NDP packets).\n");
  printf("\t--igmp (will display only IGMP packets).\n");
  printf("\t--mld (will display only MLD packets).\n");
  printf("\tUnless protocols are explicitly specified, all (i.e., all content, "
         "regardless of protocol) are considered for printing.\n");
  printf(
      "\t-n 10 (specifies the number of packets to display, i.e., the \"time\" "
      "the program runs; if not specified, only one packet is displayed)\n");
  printf("\tAll arguments can be in any order.\n\n");
  printf("Author: René Češka <xceska06@fit.vutbr.cz>");

  printf("\n\n");
  printf("Example: ./ipk-sniffer -i eth0 --arp --ndp\n");
}

/**
 * @brief formats timestamp to ISO 8601
 *
 * @param ts
 * @param timestmp
 */
void format_timestamp(struct timeval ts, char *timestmp) {
  struct tm *ltime;
  char timestr[100];
  ltime = localtime(&ts.tv_sec);
  strftime(timestr, sizeof timestr, "%FT%T%z", ltime);
  sprintf(timestmp, "%s.%06ld", timestr, ts.tv_usec);
  return;
}

/**
 * @brief prints active network devices
 *
 */
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

/**
 * @brief prints packet data
 *
 * @param packet
 * @param packet_header
 */
void print_packet_data(const u_char *packet,
                       const struct pcap_pkthdr *packet_header) {
  bpf_u_int32 i = 0;
  while (i < packet_header->len) {
    // print offset
    fprintf(stdout, "0x%04x:\t", i);

    // print hex
    for (unsigned int j = i; j < i + 16; j++) {
      if (j < packet_header->len) {
        fprintf(stdout, "%02x ", packet[j]);
      } else {
        fprintf(stdout, "   ");
      }
    }
    // ptrint ascii
    for (unsigned int j = i; j < i + 16 && j < packet_header->len; j++) {

      if (j == i + 8) {
        fprintf(stdout, " ");
      }

      if (j == i - 8 && i != 0) {
        fprintf(stdout, " ");
      }
      // is printable
      if (packet[j] >= 32 && packet[j] <= 126) {
        fprintf(stdout, "%c", packet[j]);
      } else {
        fprintf(stdout, ".");
      }
    }
    fprintf(stdout, "\n");
    i += 16;
  }
}

/**
 * @brief Get the ipv4 packet info
 *
 * @param packet
 * @param packet_header
 * @param packet_data
 */
void get_ipv4_packet_info(const u_char *packet,
                          const struct pcap_pkthdr *packet_header,
                          packet_data_t *packet_data) {

  const u_char *ip_header;

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
}

/**
 * @brief Get the ipv6 packet info
 *
 * @param packet
 * @param packet_header
 * @param packet_data
 */
void get_ipv6_packet_info(const u_char *packet,
                          const struct pcap_pkthdr *packet_header,
                          packet_data_t *packet_data) {

  const u_char *ip_header;

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
    } else if (type == 128 || type == 129) {
      packet_data->icmp6_request_response = true;
    }
    break;
  }
}

/**
 * @brief Get the arp packet info
 *
 * @param packet
 * @param packet_header
 * @param packet_data
 */
void get_arp_packet_info(const u_char *packet,
                         const struct pcap_pkthdr *packet_header,
                         packet_data_t *packet_data) {
  const u_char *arp_header;
  arp_header = packet + ETHERNET_HEADER_LENGHT;

  if (*(arp_header + 2) == 0x08) { // ipv4
    inet_ntop(AF_INET, (struct in_addr *)(arp_header + 14),
              packet_data->source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, (struct in_addr *)(arp_header + 24),
              packet_data->destination_ip, INET_ADDRSTRLEN);

  } else if (*(arp_header + 2) == 0x86 && *(arp_header + 4) == 0xdd) { // ipv6
    inet_ntop(AF_INET6, (struct in6_addr *)(arp_header + 14),
              packet_data->source_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, (struct in6_addr *)(arp_header + 24),
              packet_data->destination_ip, INET_ADDRSTRLEN);
  }
  // filter ethernet type
  strcpy(packet_data->protocol, "ARP");
}

/**
 * @brief fixed version of ntoa that doesnt reamove leading zeroes
 *
 * @param addr
 * @return char*
 */
char *ntoa_fixed(const struct ether_addr *addr) {
  char *str = (char *)malloc(18);
  sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x", addr->ether_addr_octet[0],
          addr->ether_addr_octet[1], addr->ether_addr_octet[2],
          addr->ether_addr_octet[3], addr->ether_addr_octet[4],
          addr->ether_addr_octet[5]);
  return str;
}

/**
 * @brief Packet handler
 *
 * @param conf
 * @param packet_header
 * @param packet_body
 * @return int - 1 when packet was processed, 0 when packet was filtered out
 */
int packet_handler(u_char conf[], const struct pcap_pkthdr *packet_header,
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
      .icmp6_request_response = false,
      .source_port = 0,
      .destination_port = 0,
  };
  argsT args = *(argsT *)conf;

  // gets the ethernet header
  eth_header = (struct ether_header *)packet_body;
  // gets timestamp
  char timestamp[100];
  format_timestamp(packet_header->ts, timestamp);
  strcpy(packet_data.timestamp, timestamp);

  // gets mac addresses from ethernet header
  strcpy(packet_data.source_mac,
         ntoa_fixed((const struct ether_addr *)&eth_header->ether_shost));
  strcpy(packet_data.destination_mac,
         ntoa_fixed((const struct ether_addr *)&eth_header->ether_dhost));
    //gets data from packet
  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
    get_ipv4_packet_info(packet_body, packet_header, &packet_data);
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
    get_arp_packet_info(packet_body, packet_header, &packet_data);
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
    get_ipv6_packet_info(packet_body, packet_header, &packet_data);
  }
    //filters
  if ((args.tcp == 1 && strcmp(packet_data.protocol, "TCP") == 0) ||
      (args.udp == 1 && strcmp(packet_data.protocol, "UDP") == 0) ||
      (args.icmp4 == 1 && strcmp(packet_data.protocol, "ICMP4") == 0) ||
      (args.icmp6 == 1 && packet_data.icmp6_request_response == 1) ||
      (args.arp == 1 && strcmp(packet_data.protocol, "ARP") == 0) ||
      (args.IGMP == 1 && packet_data.IGMP == true) ||
      (args.NDP == 1 && packet_data.NDP == true) ||
      (args.MLD == 1 && packet_data.MLD == true) ||
      (args.tcp == 0 && args.udp == 0 && args.icmp4 == 0 && args.icmp6 == 0 &&
       args.arp == 0 && args.IGMP == 0 && args.NDP == 0 && args.MLD == 0)) {

    if (args.port == 0 || args.port == packet_data.source_port ||
        args.port == packet_data.destination_port ||
        ((strcmp(packet_data.protocol, "TCP") != 0) &&
         (strcmp(packet_data.protocol, "UDP") != 0))) {
      if (strcmp(packet_data.timestamp, "") != 0)
        fprintf(stdout, "timestamp: %s\n", packet_data.timestamp);
      if (strcmp(packet_data.source_mac, "") != 0)
        fprintf(stdout, "src MAC: %s\n", packet_data.source_mac);
      if (strcmp(packet_data.destination_mac, "") != 0)
        fprintf(stdout, "dst MAC: %s\n", packet_data.destination_mac);
      if (packet_header->len > 0)
        fprintf(stdout, "frame length: %d bytes\n", packet_header->len);
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
      return 1;
    }
  }
  return 0;
}

int main(int argc, const char *argv[]) {
  signal(SIGINT, INThandler);
  argsT args = parseArgs(argc, argv);
  if (args.help) {
    printHelp();
    return 0;
  } else if (args.err) {
    printHelp();
    return 1;
  }
  if (strcmp(args.interface, "") == 0 ||
      (!args.arp && !args.icmp4 && !args.icmp6 && !args.tcp && !args.udp &&
       !args.num && !args.port && strcmp(args.interface, "") == 0)) {
    print_active_ndevices();
    return 0;
  }
  char error_buffer[PCAP_ERRBUF_SIZE];
  handle = pcap_create(args.interface, error_buffer);
  pcap_set_promisc(handle, 1);
  pcap_set_snaplen(handle, 2048);
  pcap_set_timeout(handle, 100);
  pcap_activate(handle);
  if (pcap_datalink(handle) != DLT_EN10MB) {
    printf("Wrong datalink type");
    return 1;
  }

  int processed_packets = 0;
  //main loop for processing packets
  while (args.num > processed_packets) {
    const u_char *packet_body;
    struct pcap_pkthdr *packet_header;
    pcap_next_ex(handle, &packet_header, &packet_body);
    processed_packets +=
        packet_handler((u_char *)&args, packet_header, packet_body);
  }
  pcap_close(handle);
  return 0;
}
