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
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pcap/pcap.h>

#elif _WIN32 // windows header files


#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>

#pragma comment(lib, "Ws2_32.lib")

#define bzero(b, len) (memset((b), '\0', (len)), (void)0)
#define bcopy(b1, b2, len) (memmove((b2), (b1), (len)), (void)0)

#endif


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
//TPDO:rewrite
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}


//TPDO:rewrite
void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet_body
)
{
    //printf("Packet captured");
    print_packet_info(packet_body, *packet_header);
    printf("\n");
    return;
}

int main(int argc, const char *argv[]) {

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
    printf("%d\n",pcap_set_rfmon(handle, 1));
     printf("%d\n",pcap_set_promisc(handle, 1)); /* Capture packets that are not yours */
     printf("%d\n",pcap_set_snaplen(handle, 2048)); /* Snapshot length */
     printf("%d\n",pcap_set_timeout(handle, 100)); /* Timeout in milliseconds */
     printf("%d\n",pcap_activate(handle));

        /* Snapshot length is how many bytes to capture from each packet. This includes*/
    int snapshot_length = 1024;
    /* End the loop after this many packets are captured */
    u_char *my_arguments = NULL;

    printf("%d",pcap_loop(handle, 100, my_packet_handler, my_arguments));
    /* handle is ready for use with pcap_next() or pcap_loop() */
    printf("%s",error_buffer);
    pcap_close(handle);
    return 0;


}