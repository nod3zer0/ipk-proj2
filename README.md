version: 0.9.0

          Project 2 - ZETA:
             __   __     ______     ______   __     __     ______     ______     __  __
            /\ "-.\ \   /\  ___\   /\__  _\ /\ \  _ \ \   /\  __ \   /\  == \   /\ \/ /
            \ \ \-.  \  \ \  __\   \/_/\ \/ \ \ \/ ".\ \  \ \ \/\ \  \ \  __<   \ \  _"-.
             \ \_\\"\_\  \ \_____\    \ \_\  \ \__/".~\_\  \ \_____\  \ \_\ \_\  \ \_\ \_\
              \/_/ \/_/   \/_____/     \/_/   \/_/   \/_/   \/_____/   \/_/ /_/   \/_/\/_/

                   ______     __   __     __     ______   ______   ______     ______
                  /\  ___\   /\ "-.\ \   /\ \   /\  ___\ /\  ___\ /\  ___\   /\  == \
                  \ \___  \  \ \ \-.  \  \ \ \  \ \  __\ \ \  __\ \ \  __\   \ \  __<
                   \/\_____\  \ \_\\"\_\  \ \_\  \ \_\    \ \_\    \ \_____\  \ \_\ \_\
                    \/_____/   \/_/ \/_/   \/_/   \/_/     \/_/     \/_____/   \/_/ /_/


source [4]


author: René Češka <xceska06@stud.fit.vutbr.cz>



Network analyzer that is able to capture and filter packets on a specific network interface.

## Usage

Usage: ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}

Options:
        -i eth0 (just one interface to sniff) or --interface. If this parameter is not specified (and any other parameters as well), or if only -i/--interface is specified without a value (and any other parameters are unspecified), a list of active interfaces is printed.
        -t or --tcp (will display TCP segments and is optionally complemented by -p functionality).
        -u or --udp (will display UDP datagrams and is optionally complemented by-p functionality).
        -p 23 (extends previous two parameters to filter TCP/UDP based on port number; if this parameter is not present, then no filtering by port number occurs; if the parameter is given, the given port can occur in both the source and destination part of TCP/UDP headers).
        --icmp4 (will display only ICMPv4 packets).
        --icmp6 (will display only ICMPv6 echo request/response).
        --arp (will display only ARP frames).
        --ndp (will display only ICMPv6 NDP packets).
        --igmp (will display only IGMP packets).
        --mld (will display only MLD packets).
        Unless protocols are explicitly specified, all (i.e., all content, regardless of protocol) are considered for printing.
        -n 10 (specifies the number of packets to display, i.e., the "time" the program runs; if not specified, only one packet is displayed)
        All arguments can be in any order.
        --help displays help message



## Testing

Testing was done using tool tcpreplay[2] which can replay pcap files. I used pcap files from [1]. All used pcap files are in folder tests.
Output of ipk-sniffer was compared to output of Wireshark[3].

### Here are some examples of tests that I have done:

#### icmp4

testing icmp4 packet filtering

![icmp4-terminal](/doc-images/tests/term-icmp4)
![icmp4-wireshark](/doc-images/tests/wire-icmp4)

#### igmp

testing igmp packet filtering

![igmp-terminal](/doc-images/tests/term-igmp)
![igmp-wireshark](/doc-images/tests/wire-igmp)

#### ivp6-tcp

testing ipv6 tcp packet filtering

![ipv6-tcp-terminal](/doc-images/tests/term-ipv6_tcp)
![ipv6-tcp-wireshark](/doc-images/tests/wire-ipv6_tcp)

#### port filtering

testing port filtering

existing packet:

![port-terminal](/doc-images/tests/term-port-succes)

nonexisting packet:

![port-terminal](/doc-images/tests/term-port-fail)

#### arp port

testing what happens when port is specified with arp

![arp-port-terminal](/doc-images/tests/term-arp_port)

- port argument is ignored as expected

# references
[1] https://packetlife.net/captures/
[2] https://tcpreplay.appneta.com/
[3] https://www.wireshark.org/



----------------------------------------------
This client sends exactly what user types. Commands are specified in IPK Calculator Protocol [1] . There are no timeouts, so server can compute it`s response for as long as user is willing to wait. If user wants to end program, at any time he can send SIGINT (CTRL +C) to end program.


## Theory

Most of knowledge needed to understand how this project works can be obtained in third presentation from ipk subject "Programování síťových aplikací" [2].
This project was also inspired by Stubs, accessible in project assignment repository [3].

## Extensions to assignment

This client also supports domain names in place of ip address

## Supported Platforms

### Linux

- tested on: Manjaro linux, NixOS
- What works:
  - All of the functionality in the assignment
  - Hostnames in place of ipv4 address

### Windows

- tested on: Windows 10
- What works:
  - Most of the functionality of linux version
- What doesn't:
  - Windows version supports only ipv4 addresses as hostname
  - Windows version uses ctrl + / (SIGQUIT) for forcefull shutdown of client when client is waiting for message from server after Ctrl + C (SIGINT) was send, because windows limitations


## Interesting Code

### TCPreceive

TCP message from server can be split into multiple packets. This function keeps receiving packets and printing them to stdout until newline is found.
```c
int TCPreceive(int client_socket) {
  // initialize varriables
  char buf[BUFSIZE];
  bzero(buf, BUFSIZE);
  char temp[BUFSIZE];
  bzero(buf, BUFSIZE);
  int tempPointer = 0;

  // receives message from server until newline is found
  do {
    bzero(buf, BUFSIZE);

    if (recv(client_socket, buf, BUFSIZE - 1, 0) < 0)
      perror("ERR:receiving message");
    // prints response
    printf("%s", buf);
    fflush(stdout);

    // if message is longer than 5 characters, it is not BYE
    if (tempPointer < 5) {
      strcpy(temp + tempPointer, buf);
      tempPointer++;
    }

    // checks if server sends BYE
    if (tempPointer < 5 && strcmp(temp, "BYE\n") == 0) {
      return 1;
    }
    // if message is empty, continue receiving
    if (strlen(buf) < 1) {
      continue;
    }
  } while (buf[strlen(buf) - 1] != '\n');
  return 0;
}

```

### Hostname  parsing

Parsing of hostname was split into two functions because of windows depreceated function gethostbyname. Because this project is mainly for linux, it was decided to support only ipv4 addresses in windows version.

```c
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
```

### Signal handling

For SIGINT handling was used global struct, that holds information needed for closing socket.
```c
typedef struct interruptVarriables_t {
  int client_socket;
  bool connected;
  bool interrupted;
} interruptVarriablesT;
```

Linux version supports sending second SIGINT to skip waiting for response from server and close socket. Because Windows supports only signal and not rest of signal handling, it was decided to use SIGQUIT for this purpose, even thought it is not ideal. This decision was made because windows is not main target of this project.
```c
void INThandler(int sig) {

#ifdef __linux__
  // unblock sigint
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGINT);
  if (sigprocmask(SIG_UNBLOCK, &set, NULL) == -1) {
    perror("sigprocmask");
    exit(EXIT_FAILURE);
  }
//  .
//  .
//  .
```

```c
//... main(argc, argv){ ...
// .
// .
// sigint setup
#ifdef __linux__
  struct sigaction sa;
  sa.sa_handler = INThandler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(SIGINT, &sa, NULL);
#elif _WIN32
  signal(SIGINT, INThandler);
#endif
//.
//.
//.
```

## Testing

### Automated script for arguments

For testing arguments of program was written python script, because there could be lot of edge cases. So it was easier to automate it.

Tests can be edited in folder /tests/arguments/tests.csv.
Format of tests is:
`name of test, starting arguments, expected return code`

At the moment of writing this readme it contains these tests:

```
missing port udp,ipkcpc -h 127.0.0.1 -m udp,1
missing host udp,ipkcpc -p 9999 -m udp,1
missing mode,ipkcpc -h 127.0.0.1,1
port too small udp,ipkcpc -h 127.0.0.1 -p 0 -m udp,1
port too big udp,ipkcpc -h 127.0.0.1 -p 65536 -m udp,1
missing port tcp,ipkcpc -h 127.0.0.1 -m tcp,1
missing host tcp,ipkcpc -p 9999 -m tcp,1
missing mode,ipkcpc -h 127.0.0.1,1
port too small tcp,ipkcpc -h 127.0.0.1 -p 0 -m tcp,1
port too big tcp,ipkcpc -h 127.0.0.1 -p 65536 -m tcp,1
```
Tests can be run by command: `make test`

- note: tests need `python3` installed


### Udp and tcp tests

Because there was needed to be setup two servers, one for tcp and one for udp, and the low amount of tests needed to be done on this part it made more sense do them manually.

Server was setup on testing computer in virtual machine with NixOs on address 192.168.122.150:8888. As server was used ipkcpd from assignment. Sometimes instead of ipkcpd was used netcat, because it provided more information about connection.
Client has run on the same computer with address 192.168.122.1.
Testing computer run Manjaro linux as it's OS.
#### UDP

correct input
```
./ipkcpc -h 192.168.122.150 -p 8888 -m udp
(+ 1 2)
OK:3
```
incorrect input
```
./ipkcpc -h 192.168.122.150 -p 8888 -m udp
dsaada
ERR:Could not parse the message
```


#### TCP

server shutdown

```
./ipkcpc -h 192.168.122.150 -p 8888 -m tcp
ERROR:connect: Connection refused
```

correct inputs

```
./ipkcpc -h 192.168.122.150 -p 8888 -m tcp
HELLO
HELLO
SOLVE (+ 1 2)
RESULT 3
SOLVE (* 2 3)
RESULT 6
SOLVE (/ 4 2)
RESULT 2
SOLVE (- 1 2)
RESULT -1
BYE
BYE
```

incorect input

```
/ipkcpc -h 192.168.122.150 -p 8888 -m tcp
lkjdsa
BYE
```

incorect input after connection established

```
./ipkcpc -h 192.168.122.150 -p 8888 -m tcp
HELLO
HELLO
dad
BYE
```

connection disrupted after connection established - server shutdown

```
./ipkcpc -h 192.168.122.150 -p 8888 -m tcp
HELLO
HELLO
SOLVE (+ 3 4)
RESULT 7

BYE

```

connection disrupted after connection established - server connection severed

- note: application waits till connection is recovered or user sends sigint

```
./ipkcpc -h 192.168.122.150 -p 8888 -m tcp
HELLO
HELLO


^CSigint received, sending BYE, waiting for server to respond. To skip this process press ctrl+c again.
^C
```

sigint after connection established

- note: socket was closed before application shutdown and server received BYE

```
./ipkcpc -h 192.168.122.150 -p 8888 -m tcp
HELLO
HELLO
^CSigint received, sending BYE, waiting for server to respond. To skip this process press ctrl+c again.
BYE
```

impossible address

```
./ipkcpc -h 192.222.323.323 -p 8888 -m tcp
ERROR: no such host as 192.222.323.323
```

open port but server shutdown

```
./ipkcpc -h 192.168.122.150 -p 8888 -m tcp
ERROR:connect: Connection refused
```

message received in parts

- note: each letter from server was in different packet

```
./ipkcpc -h 192.168.122.150 -p 8888 -m tcp
HELLO
HELLO
BYE
BYE
```

## References

[1] [IPK Calculator Protocol]([./Protocol.md](https://git.fit.vutbr.cz/NESFIT/IPK-Projekty/src/branch/master/Project%201/Protocol.md))

[2] KOUTENSKÝ, Michal. DOLEJŠKA, Daniel. *IPK2023 – 03 – Programování (Dolejška, Koutenský)*[online]. [14.03.2023] Dostupné z: [https://moodle.vut.cz/pluginfile.php/550189/mod_folder/content/0/IPK2022-23L-03-PROGRAMOVANI.pdf?forcedownload=1](https://moodle.vut.cz/pluginfile.php/550189/mod_folder/content/0/IPK2022-23L-03-PROGRAMOVANI.pdf?forcedownload=1)

[3] KOUTENSKÝ, Michal. VESELY, Vladimir. RYSAVY, Ondrej. *Stubs*[online]. [19.03.2023] Dostupné z: [https://git.fit.vutbr.cz/NESFIT/IPK-Projekty/src/branch/master/Stubs/cpp](https://git.fit.vutbr.cz/NESFIT/IPK-Projekty/src/branch/master/Stubs/cpp)

[4] https://patorjk.com/software/taag/#p=display&f=Sub-Zero&t=network%0A%20%20sniffer : sub-zero