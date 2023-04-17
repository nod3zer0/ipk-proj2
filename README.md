version: 1.0.0

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


source [6]


author: René Češka <xceska06@stud.fit.vutbr.cz>



Network analyzer that is able to capture and filter packets on a specific network interface.

## Usage

Usage: ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}


Options:

       - -i eth0 (just one interface to sniff) or --interface. If this parameter is not specified (and any other parameters as well), or if only -i/--interface is specified without a value (and any other parameters are unspecified), a list of active interfaces is printed.

       - -t or --tcp (will display TCP segments and is optionally complemented by -p functionality).

       - -u or --udp (will display UDP datagrams and is optionally complemented by-p functionality).

       - -p 23 (extends previous two parameters to filter TCP/UDP based on port number; if this parameter is not present, then no filtering by port number occurs; if the parameter is given, the given port can occur in both the source and destination part of TCP/UDP headers).

       - --icmp4 (will display only ICMPv4 packets).

       - --icmp6 (will display only ICMPv6 echo request/response).

       - --arp (will display only ARP frames).

       - --ndp (will display only ICMPv6 NDP packets).

       - --igmp (will display only IGMP packets).

       - --mld (will display only MLD packets).
        Unless protocols are explicitly specified, all (i.e., all content, regardless of protocol) are considered for printing.

       - -n 10 (specifies the number of packets to display, i.e., the "time" the program runs; if not specified, only one packet is displayed)
        All arguments can be in any order.

       - --help displays help message


## Extensions to assignment

- At TCP, UDP, ARP, ICMP4 and ICMP6 protocols, it will write protocol name.

- When outputting interfaces it will also write their short description.

## Theory

### How ipk-sniffer works

The ipk-sniffer uses pcap library for capturing packets. When packet is captured it is passed to function according to protocol of packet (ARP, IPV4 and IPV6). In these functions are parsed values from packet headers and stored in struct `packet_data` whitch is returned.
The filtering is done by checking if values in struct `packet_data` are same as values specified by user. If they are same, packet is printed. Otherwise it is ignored.

I did not use built in filters because I wanted to use this oportunity to look closer to how packets look in raw form.

Some parts of code were inspired by these sources [4][5]

### Packet structure

#### Ethernet

Ethernet header is 14 bytes long. It's alues that ipk-sniffer is interested in are `ether_type` and source and destination MAC address. [16]

#### IPv4


It's values that ipk-sniffer is interested in are header_lenght, `protocol` and source and destination IP address. [15]

#### IPv6

IPv6 header is 40 bytes long. It's values that ipk-sniffer is interested in are `protocol` and source and destination IP address. [14]

#### TCP

TCP header is 20 bytes long. It's values that ipk-sniffer is interested in are source and destination port. [13]

#### UDP

UDP header is 8 bytes long. It's values that ipk-sniffer is interested in are source and destination port. [12]

#### ARP

ARP header is 28 bytes long. It's values that ipk-sniffer is interested in are `opcode` and source and destination IP addresses. [11]

#### ICMPv4

It's type is stored in it's IPV4 header in `protocol`. [10]

#### ICMPv6

It's type is stored in it's IPV6 header in `protocol`. [9]
#### IGMP

It's type is stored in it's IPV4 header in `protocol`. [8]

#### MLD

MLD is type of ICMPv6 packet. It's value that sniffer is interested in is `type`. [7]

#### NDP

NDP is type of ICMPv6 packet. It's value that sniffer is interested in is `type`. [7]

#### ICMPv6 echo request/response

echo request and response are types of ICMPv6 packet. It's value that sniffer is interested in is `type`. [7]

## Interesting code

### Filtering

Filtering was done by checking if values in struct `packet_data` are same as values specified by user. If they are same, packet is printed. Otherwise it is ignored.

```c++
if ((args.tcp == 1 && strcmp(packet_data.protocol, "TCP") == 0) ||
      (args.udp == 1 && strcmp(packet_data.protocol, "UDP") == 0) ||
      (args.icmp4 == 1 && strcmp(packet_data.protocol, "ICMP4") == 0) ||
      (args.icmp6 == 1 && packet_data.icmp6_request_response == 1) ||
      (args.arp == 1 && strcmp(packet_data.protocol, "ARP") == 0) ||
      (args.IGMP == 1 && packet_data.IGMP == true) ||
      (args.NDP == 1 && packet_data.NDP == true) ||
      (args.MLD == 1 && packet_data.MLD == true) ||
      (args.tcp == 0 && args.udp == 0 && args.icmp4 == 0 && args.icmp6 == 0 &&
       args.arp == 0 && args.IGMP == 0 && args.NDP == 0 && args.MLD == 0))
       //.
       //.
       //.
       //.
```

### formating timestamp

Timestamp is formated by using `strftime` function.

```c++

void format_timestamp(struct timeval ts, char *timestmp) {
  struct tm *ltime;
  char timestr[100];
  ltime = localtime(&ts.tv_sec);
  strftime(timestr, sizeof timestr, "%FT%T%z", ltime);
  sprintf(timestmp, "%s.%06ld", timestr, ts.tv_usec);
  return;
}
```


## Testing

Testing was done using tool tcpreplay[2] which can replay pcap files. I used pcap files from [1]. All pcap files used are in folder tests.
Output of ipk-sniffer was compared to output of Wireshark[3].
Testing Environment was nix-os from asignement.
Tests were also done on Manjaro Linux.

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
![ipv6-tcp-wireshark](/doc-images/tests/wire-ipv6-tcp)

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
[4] https://www.tcpdump.org/pcap.html
[5] https://www.devdungeon.com/content/using-libpcap-c
[6] https://patorjk.com/software/taag/#p=display&f=Sub-Zero&t=network%0A%20%20sniffer : sub-zero
[7] https://en.wikipedia.org/wiki/ICMPv6
[8] https://en.wikipedia.org/wiki/Internet_Group_Management_Protocol
[9] https://en.wikipedia.org/wiki/ICMPv6
[10] https://cs.wikipedia.org/wiki/ICMP
[11] https://cs.wikipedia.org/wiki/Address_Resolution_Protocol
[12] https://en.wikipedia.org/wiki/User_Datagram_Protocol
[13] https://cs.wikipedia.org/wiki/Transmission_Control_Protocol
[14] https://en.wikipedia.org/wiki/IPv6_packet
[15] https://en.wikipedia.org/wiki/Internet_Protocol_version_4
[16] https://en.wikipedia.org/wiki/Ethernet_frame

