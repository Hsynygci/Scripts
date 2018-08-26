
import socket, sys
from struct import *
import datetime, time
import os

if os.path.isfile('Raw_data'): 
    os.remove('flow_data_info')
    os.remove('flow_data')
    os.remove('Raw_data')

flow_data = []
raw_data = []
tcp_streamcounter = 0


#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b

def gettimestamp():
    return "%s %s %s" % (datetime.datetime.now().strftime("%d-%b-%Y %H:%M:%S.%f"), time.time(), time.tzname[0])

def flowsendrecvsize(flow_pair):
    senddatabyflow = 0
    receivedatabyflow = 0

    for raw in raw_data:
        raw1 = raw.split(':')[0]+':'+raw.split(':')[1]+':'+raw.split(':')[2]+':'+raw.split(':')[3]
        raw2 = raw.split(':')[2]+':'+raw.split(':')[3]+':'+raw.split(':')[0]+':'+raw.split(':')[1]
        if  flow_pair == raw1:
            senddatabyflow += int(raw.split(':')[11])
        elif flow_pair == raw2:
            receivedatabyflow += int(raw.split(':')[11])

    return ' Send: '+ str(senddatabyflow) + ' Receive: ' + str(receivedatabyflow) + ' Total: ' +str(senddatabyflow + receivedatabyflow)

def flowduration(flow_pair):
    for raw in raw_data:
        raw1 = raw.split(':')[0]+':'+raw.split(':')[1]+':'+raw.split(':')[2]+':'+raw.split(':')[3]
        if flow_pair == raw1:
            timestart = float(raw.split(':')[7].split(' ')[1])
            break
    for raw in reversed(raw_data):
        if flow_pair == raw1:
            timefinito = float(raw.split(':')[7].split(' ')[1])
            break
    
    return timefinito-timestart



def checknewflow(ip_pair, data):
    #ip_pair = s_addr + ':' + str(source_port) + ':' + d_addr + ':' + str(dest_port)
    if len(flow_data) == 0:
        flow_data.append(ip_pair)
        flow_file.write('\n' + str(ip_pair+' : '+data))

    test1 = ip_pair.split(':')[0] +':'+ ip_pair.split(':')[1] +':'+ ip_pair.split(':')[2] +':'+ ip_pair.split(':')[3]
    test2 = ip_pair.split(':')[2] +':'+ ip_pair.split(':')[3] +':'+ ip_pair.split(':')[0] +':'+ ip_pair.split(':')[1]

    if test1 in flow_data:
        #same
        print 'same'
    elif test2 in flow_data:
        #same
        print 'same'
    else:
        print 'new'
        flow_file.write('\n' + str(ip_pair+' : '+data))
        flow_data.append(ip_pair)
        
  
#create a AF_PACKET type raw socket (thats basically packet level)
#define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()


while True:
    packet = s.recvfrom(65565)
    packet = packet[0]

    # Ethernet Header:
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|       Ethernet destination address (first 32 bits)            |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #| Ethernet dest (last 16 bits)  |Ethernet source (first 16 bits)|
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|       Ethernet source address (last 32 bits)                  |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|        Type code              |                               |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    eth_length = 14 # parse ethernet header
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth[2])
    #print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)
    
    # RFC 791 IP Header:
    #0                   1                   2                   3
    #0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|Version|  IHL  |Type of Service|          Total Length         |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|         Identification        |Flags|      Fragment Offset    |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|  Time to Live |    Protocol   |         Header Checksum       |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                       Source Address                          |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                    Destination Address                        |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                    Options                    |    Padding    |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    if eth_protocol == 8: # IP
        ip_header = packet[eth_length:20+eth_length]
        iph = unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4 # 0100 0101 --> 000 0100 drops 4 least significant bits.
        ihl = version_ihl & 0xF    # 0100 0101 --> 0101 mask least significant nybble with ones.
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);

        #print ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
        Ethernet_info = ' Protocol : ' + str(protocol) +','+  ' Source Address : ' + str(s_addr) +','+  ' Destination Address : ' + str(d_addr)
        # TCP header format RFC 793
        #     0                   1                   2                   3
        #     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #    |          Source Port          |       Destination Port        |
        #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #    |                        Sequence Number                        |
        #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #    |                    Acknowledgment Number                      |
        #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #    |  Data |           |U|A|P|R|S|F|                               |
        #    | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
        #    |       |           |G|K|H|T|N|N|                               |
        #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #    |           Checksum            |         Urgent Pointer        |
        #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #    |                    Options                    |    Padding    |
        #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #    |                             data                              |
        #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
        if protocol == 6 : #TCP    
            tcp_header = packet[iph_length + eth_length:iph_length + eth_length+20]
            tcp_header = unpack('!HHLLBBHHH', tcp_header)
            source_port = tcp_header[0]
            dest_port = tcp_header[1]
            sequence = tcp_header[2]
            ack = tcp_header[3]
            doff_reserved = tcp_header[4]
            tcp_header_length = doff_reserved >> 4
            header_size = eth_length + iph_length + tcp_header_length * 4
            data_size = len(packet) - header_size
            data = packet[header_size:]
            temp_pair = s_addr + ':' + str(source_port) + ':' + d_addr + ':' + str(dest_port)
            temp_data = 'Timestamp : ' + gettimestamp() + ' : Protocol : TCP ' + ' : data size : ' + str(data_size)
            raw_data.append(temp_pair+':'+temp_data)

            flow_file= open('flow_data','a')
            checknewflow(temp_pair, temp_data)
            flow_file.close()

            flowdata_file= open('flow_data_info','w')
            for flow in flow_data:
                flowdata_file.write('Flow: ' + flow + ' : ' + str(flowsendrecvsize(flow)) + ' Duration : ' + str(flowduration(flow)) +'\n')
            flowdata_file.close()

            raw_file = open('Raw_data', 'a')
            raw_file.write('\n' + temp_pair + ' : ' + temp_data )
            raw_file.close()

        elif protocol == 17 : #UDP
            udp_header_length = 8
            udp_header = packet[iph_length + eth_length:iph_length + eth_length+8]
            udp_header = unpack('!HHHH', udp_header)
            source_port = udp_header[0]
            dest_port = udp_header[1]
            length = udp_header[2]
            checksum = udp_header[3]
            header_size = eth_length + iph_length + udp_header_length
            data_size = len(packet) - header_size
            data = packet[header_size:] 

            temp_pair = s_addr + ':' + str(source_port) + ':' + d_addr + ':' + str(dest_port)
            temp_data = 'Timestamp : ' + gettimestamp() + ' : Protocol : UDP ' + ' : data size : ' + str(data_size)
            raw_data.append(temp_pair+':'+temp_data)

            flow_file= open('flow_data','a')
            checknewflow(temp_pair, temp_data)
            flow_file.close()   

            flowdata_file= open('flow_data_info','w')
            for flow in flow_data:
                flowdata_file.write('Flow: ' + flow + ' : ' + str(flowsendrecvsize(flow)) + ' Duration : ' + str(flowduration(flow)) +'\n')
            flowdata_file.close()

            raw_file = open('Raw_data', 'a')
            raw_file.write('\n' + temp_pair + ' : ' + temp_data)
            raw_file.close() 


        else:
            print 'Protocol not defined!'

