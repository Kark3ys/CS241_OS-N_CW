# CS241_OS-N_CW
Archive of CS241 OS&amp;N coursework, threadpooled approach to sniffing and analysing incoming packet data in C.
Following text from the coursework webpage: [https://warwick.ac.uk/fac/sci/dcs/teaching/material/cs241/coursework17-18/](https://warwick.ac.uk/fac/sci/dcs/teaching/material/cs241/coursework17-18/)

## CS241 Coursework 2017-2018

### The Task

For this coursework you will implement a basic intrusion detection system. This will test your understanding of TCP/IP protocols (networks) and threading (OS) as well as your ability to develop a non-trivial program in C. The coursework contributes 20% of the total marks towards the module.

You have been provided with an application skeleton that is able to intercept (sniff) incoming packets and print them to the screen. The code uses the libpcap library to receive packets and strips the outer-most layer of the protocol stack. The goal of this coursework is to extend the skeleton to detect potentially malicious traffic in high-throughput networks. The key deliverables of this coursework and their associated weightings are as follows.

- Extend the skeleton to efficiently intercept and correctly parse the IP and TCP protocol layers. (~30%)
- Identify suspicious packets. Produce a report containing a breakdown of the malicious activity detected to be printed when the program exits. (~20%)
- Implement a threading strategy to allow your code to deal with high packet throughput. (~20%)
- Write a report no more than 2 pages in length (excluding references) explaining the design, implementation and testing of your solution. (~20%)
- The final ~10% is awarded for code quality and adherence to relevant software engineering principles.

You must base your solution on the skeleton provided and it must be written entirely in the C programming language. You should only consider IPV4 - there are no additional marks available for IPV6 functionality. You may choose to use appropriate academic or industrial literature, which should be referenced appropriately. When writing an academic report, you should not write in first person (i.e., Don't write "I did this, I did that, etc.").

### Code Skeleton
The coursework skeleton consists of several files, each with a specific purpose:

#### Makefile
As this project spans multiple files we have provided a makefile to automate the build process for you. To compile your solution you should change into the src directory and then run the `make` command. This will build the application binary "../build/idsniff". Your solution should not require changes to this file.

#### main.c
This file hosts the application entry point. It also contains logic to parse command line arguments, allowing you to set the verbose flag and specify the network interface to sniff. Your solution should not require changes to this file.

#### sniff.c
This file contains the `sniff` function which captures packets from the network interface and passes them to your logic. A utility method called `dump` is also provided to output the raw packet data when debug mode is enabled. You should study this function carefully as it demonstrates how to parse a packet's ethernet header.

#### analysis.c
This file is where you should put code to analyse packets and identify threats. Your logic should be called from the `analyse` method which runs each time a packet is intercepted.

#### dispatch.c
This file is where you should put code to parallelise your system. At the moment, the `dispatch` method simply calls the `analyse` method in `analysis.c` . This sequential, single-threaded behaviour should be replaced by code to distribute work over multiple threads.

### Specification
The project is split into three parts and deals with a specific concept. Please note that these parts are not discrete excercises. You are not expected to complete them in order, and they are not seperate courseworks. You should read all three parts before you start the coursework. In particular, when writing code to parse packet headers required for part 1 you should be mindful of thread safety.

#### Part 1 - Packet Sniffing
You should start this coursework by writing code to parse the Ethernet, TCP, ARP and IP headers in `analysis.c`. This code will be used in Part 2 of this coursework by your packet analysis routines. Before you begin you should review the network primer page - this covers the OSI model and the packet structure which you will be expected to parse.

**Hint:** If you get stuck with parsing headers you should read thedump method insniff.c as it demonstrates how to parse the Ethernet header (link layer in the OSI model). To understand how this method works remember that the ethernet frame is 14 bytes in size and has the following format (note one tick mark represents one bit, meaning there are 32 bits = 4 bytes per complete line) :
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Destination MAC                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Destination MAC (Cont.)    |           Source MAC          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Source MAC (Cont.)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Protocol             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
Due to C's contiguous memory layout guarantees we know that the elements of a struct will be arranged sequentially in memory. We can therefore define a struct which maps to this format, or use the one provided in <netinet/if_ether.h>:
```
// if_ether.h excerpt

#define ETH_ALEN 6 /* Octets (bytes) in one ethernet addr */
#define ETH_HLEN 14 /* Total octets in header */

struct ether_header {
  u_char ether_dhost[6];
  u_char ether_shost[6];
  u_short ether_type;
};
```
Hopefully you should be able to see how the struct maps to the ethernet format - 6 bytes for the destination address, 6 for the source address and 2 bytes for the protocol.If you look up this documentation online, make sure taht you refer to the version that applies to your operating system.


Once we have this struct defined we can use it to read values directly from the packet data:
```
struct ether_header * eth_header = (struct ether_header *) data;
printf("\nType: %hu\n", eth_header->ether_type);
```
The code above shows you how to parse the outermost layer of the packet and access members of the ethernet header. However, while this will allow you to parse each field into a C structure there is one additional complication to consider - network byte order. In order for different machines to communicate, a standard ordering of bytes for multi-byte data types (e.g short and int) must be observed. This is because some machines place the most significant byte first (big-endian) and others place the least significant byte first (little-endian). With this in mind, when multi-byte values are read from a socket they must be converted from network byte order, to the order which the current machines uses. Since ether_type is a multi-byte value (a short), it will need to be converted before being printed or used in any comparisons. To do this, the function `ntohs` can be used as follows.
```
#include <netinet/in.h>
...
unsigned short ethernet_type = ntohs(eth_header->ether_type);
```
For part 2 you will need to repeat this process to access information added at the various network layers.

To score highly in this part your solution must contain code which can successfully parse the relevant packet headers. We do not expect you to parse every type of header imaginable, only those which will be required to complete part 2. You should also take a look at the `sniff` method in `sniff.c` to see how packets are captured and passed on to your logic. **Hint:** The current implementation works but it could be improved by using libpcap's own network loop.

#### A note on PCAP filters
PCAP exposes a domain specific language which allows you to specify packet filters. This feature may not be used to complete the coursework. You must implement the logic to access and process packet headers manually. A central aim of this coursework is for you to become familiar with the network stack; marks will be deducted from solutions which rely on external parsing or filtering logic.

#### Part 2 - Intrusion Detection
Now that you are able to parse individual packets the next step is to analyze them. You should write code to detect the three suspicious scenarios outlined below. Your program should record any malicious activity and print a report on exit. This report should show a clear breakdown of any malicious activity detected. Your output should look something like the following (feel free to add extra stuff, but we need at least these lines for functional testing):
```
cs241-cw:~# ./part2 ../build/idsniff -i lo
../build/idsniff invoked. Settings:
Interface: lo
Verbose: 0
SUCCESS! Opened lo for capture
^C
Intrusion Detection Report:
4 Xmas scans (host fingerprinting)
3  ARP responses (cache poisoning)
5  URL Blacklist violations
cs241-cw:~#
```

##### Xmas Tree Scan
This is a stealthy port scanning technique used to evade detection whilst probing a target machine. This port scan sends packets with the FIN, PSH, and URG flags set, lighting the packet up like a Christmas tree. There is no standardised way for a system to respond to such a packet because in theory it should never happen. In practice different operating systems respond in different ways, a fact which attackers use to fingerprint the target system. These scan types can also sneak through certain non-stateful firewalls and packet filtering routers.

Xmas packets are always suspicious and indicate a high probability of network reconnaissance activities. You should add code to `analysis.c` to detect any packets with all these flags set. One way to test your code is to use the nmap packet sniffer which can be installed with the command `apt-get install nmap`. Once installed you can launch an Xman scan like so: `nmap -sX localhost`. Remember to instruct your sniffer to listen on the loopback interface if nmap is running on the same machine as it (`../build/idsniff -i lo`).

##### ARP Cache Poisioning
The Address Resolution Protocol (ARP) is used by systems to construct a mapping between network layer (Media Access Control) and link layer (Internet Protocol) addresses. Consider a simple scenario: two systems share a network - dcs_laptop has IP address 192.168.1.68 and is trying to communicate with *broadband_router* at 192.168.1.1. To achieve this, dcs_laptop broadcasts an ARP request asking for the MAC address of the node at 192.168.1.1. When broadband_router sees this message it responds with its MAC address. *dcs_laptop* will cache this address for future use and then use it to establish a connection.

The ARP protocol has a serious flaw in that it performs no validation. An attacker can craft a malicious ARP packet which tricks the router into associating the ip address of dcs_laptop with the attacker's own MAC address. This means all traffic bound for dcs_laptop will be redirected to the attacker, potentially exposing sensitive data or allowing for man-in-the-middle attacks. To make matters worse, ARP allows unsolicited responses, meaning dcs_laptop does not even have to send out a request - an attacker can simply broadcast a message informing all nodes to send dcs_laptop traffic to their machine.

Although ARP messages can be legitimate, the use of caching means they should be very rare. A burst of unsolicited ARP responses is a strong indication that an attacker has penetrated a network and is trying to take it over. You should add code which detects any ARP responses.

##### Blacklisted URLs
Intrusion detection systems typically watch traffic originating from the network they protect in addition to attacks coming from outside. This can allow them to detect the presence of a virus trying to connect back to a control server for example, or perhaps monitor any attempts to smuggle sensitive information to the outside world. For this excercise we have identified `www.bbc.co.uk` as a suspicious domain which we wish to monitor. Specifically we wish to be alerted when we see HTTP traffic being sent to that domain.

You should add code to process TCP packets that are sent and recieved from port 80 (i.e. the HTTP port). This code should parse a subset of the HTTP application-layer headers in order to identify the host web address. If any requests to `www.bbc.co.uk` are detected these should be flagged up as malicious.

A malicious HTTP request will look something like the following:
```
GET /news/ HTTP/1.1
Host: www.bbc.co.uk
Connection: keep-alive
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.22 (KHTML, like Gecko) Chrome/25.0.1364.172 Safari/537.22
Accept-Encoding: gzip,deflate,sdch
Accept-Language: en-GB,en-US;q=0.8,en;q=0.6
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3
```
One way to test your code is to use the wget command on your virtual machine to retrieve a webpage like so: `wget www.bbc.co.uk/news`. Whilst testing this code you should configure the sniffer to listen on the external `eth0` like this: `../build/idsniff -i eth0` (This should be the default).

#### Part 3 - Multithreading
Intrusion detection systems often monitor the traffic between the global internet and large corporate or government networks. As such they typically have deal with massive traffic volumes. In order to allow your system to handle high data rates you should make your code multi-threaded. There are several strategies you could choose to adopt to achieve this. Two common approaches are outlined below. Whatever approach you choose to implement you must remember to justify your decision in your report. For this work we will focus on POSIX threads you were introduced to in lab 3. In order to use POSIX threads, the lpthread linker flag must be added to the project makefile like so:

`LDFLAGS := -lpcap -lpthread`

##### One Thread per X Model
This approach to threading creates a new thread for each unit of work to be done (in our case our X is each packet to process) and is probably still the most common approach to threading. This model is sometimes called the Apache model after the Apache webserver which by default gives each client connection a dedicated thread. The strength of this model can be found in its simplicity and low overhead when dealing with constant light loads as no threads are kept idle. The downside to this approach is that it scales poorly under heavy or bursty load.

##### Threadpool Model
This approach creates a fixed number of threads on startup (typically one or two per processor core). When a packet arrives it is added to a work queue. The threads then try to take work from this queue, blocking when it becomes empty. The strength of this approach is that it deals better in bursty or heavy traffic scenarios as it removes the need to create threads dynamically and limits the number of threads active at any given time, avoiding thrashing. Its weakness stems from the added implementation complexity.

The bulk of your threading code should be placed in `dispatch.c`. Whichever model you choose you should deal with thread creation and work allocation here. You may find that you also have to make minor modifications to analysis.c to make your code threadsafe. In particular you should be careful when storing intrusion records to avoid any lost updates or race conditions.
