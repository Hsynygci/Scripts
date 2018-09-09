import socket
import threading
import subprocess
import sys 
import os
import collections
import time
import psutil
import urllib2
import xmltodict
import random
import struct, fcntl


port_scan_counter = 0


# + 1. Create listeners on listed ports
#   2. port specific action procedure
#       +2.2. create port scan detection algorithm
#       + 2.3. create web page Siemens hmi login page
#           +2.3.1. create bruteforce detection  
#   3. Shodan detection prevention   
#       3.1. Get current shodan IPs:
#               https://isc.sans.edu/api/threatlist/shodan/     
#       3.2. setup listener for these IP adresses.
#       3.3. If you catch, apply prevention procedure. (change; ip, mac, pc-name)
#       
#   4. create logger
#   5. Setup bash
#       5.1. apache2
#       5.2. apache2 / php configuration
#       5.3. index.php mover
#       5.4. chmod -R 775 /var/www
#       5.5. 

##Bonus
# commandline over backdoor
# hide backdoor from kernel's port list
# proactive mode, dig, whois procedure for detected ips.


#BEGIN - SHODAN PROCEDURE

def setIpAddr(iface, ip):
    SIOCSIFADDR = 0x8916
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bin_ip = socket.inet_aton(ip)
    ifreq = struct.pack('16sH2s4s8s', iface, socket.AF_INET, '\x00' * 2, bin_ip, '\x00' * 8)
    fcntl.ioctl(sock, SIOCSIFADDR, ifreq)


def shodan_IP_list():
    file = urllib2.urlopen('https://isc.sans.edu/api/threatlist/shodan/')
    data = file.read()
    file.close()

    data = xmltodict.parse(data)
    ips = []
    for i in data['threatlist']['shodan']:
        ips.append(i['ipv4']) 
    #return render_to_response('my_template.html', {'data': data})
    return ips

def get_new_hostname():
    return "DefinitelyNotHoneypot"+str(random.randint(0,76))

#dummy mac generator
def get_new_mac():
    #02:01:02:03:04:08
    return str(random.randint(10,99))+":"+str(random.randint(10,99))+":"+str(random.randint(10,99))+":"+str(random.randint(10,99))+":"+str(random.randint(10,99))+":"+str(random.randint(10,99))

def is_empty(any_structure):
    if any_structure:
        return False
    else:
        return True

def get_remote_addr():        
    raddr_list = []
    #while True:
    for net_cons in psutil.net_connections():
        if not is_empty(net_cons[4]):
            raddr_list.append(net_cons[4][0])

    return raddr_list
    

def shodan_detection():
    updated_shodan_ips = shodan_IP_list()
    remote_ips = get_remote_addr()

    if set(updated_shodan_ips).intersection(set(remote_ips)):
        return True
    else: return False

def shodan_prevention(eth):
    # 1. change ip

    #Set new ip addr
    #setIpAddr(eth, '192.168.106.145')
    #request new ip from DHCP
    command = "dhclient -r " + eth
    subprocess.call(command, stderr=subprocess.STDOUT, shell=True)

    # 2. change mac
    command = "/etc/init.d/networking stop"
    subprocess.call(command, stderr=subprocess.STDOUT, shell=True)
    #Prepare MAC
    mac =  get_new_mac()
    command = "ifconfig "+eth+" hw ether "+mac
    subprocess.call(command, stderr=subprocess.STDOUT, shell=True)
    command = "/etc/init.d/networking start"
    subprocess.call(command, stderr=subprocess.STDOUT, shell=True)

    # 3. change pc name
    new_hostname = get_new_hostname()
    command = "hostnamectl set-hostname "+new_hostname
    subprocess.call(command, stderr=subprocess.STDOUT, shell=True)
    command = "hostnamectl"
    subprocess.call(command, stderr=subprocess.STDOUT, shell=True)

def shodan_procedure(interface_name):
    while True:
        if shodan_detection():
            shodan_prevention(interface_name)
        time.sleep(20)
#END - SHODAN PROCEDURE


#BEGIN - BRUTEFORCE RELATED FUCNTIONS
def apache2_checker():
    command = "service apache2 start"
    output = subprocess.call(command, stderr=subprocess.STDOUT, shell=True)

def brute_force_detection(filepath):
    ip_pool = []
    if os.path.isfile(filepath):
        log_file = open(filepath)
        for line in log_file:
            ip_pool.append(line.split(' ')[6].split(']')[0])
            ips = collections.Counter(ip_pool)
            for i in ips.iteritems():
                if i[1]> 5:
                    print "Bruteforce attempt from %s" % i[0]
                    return
            if os.path.isfile(filepath): 
                os.remove(filepath)

def bruteforce_detection_handler():
    #open apache2 if closed
    apache2_checker()

    #check for log file
    filepath = '/var/www/html/log.txt'

    while True:
        time.sleep(3)
        client_handler = threading.Thread(target=brute_force_detection, args=(filepath, ))
        client_handler.start()
    
#END - BRUTEFORCE RELATED FUNCTIONS

#BEGIN - hONEYPOT MAIN FUNCTIONS
def create_UDP_listener(host, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    while True:
        
        print "Listener established for %s UDP port. Honeypot will be tiriggered when data received." % port
        (data, addr) = server.recvfrom(1024)
        if addr:
            print "Possible adversary IP:Port ==> %s:%d" % (addr[0], addr[1])
            print "Someone tried to reach %d port !!" % port
            udp_ip = addr[0]
            udp_port = addr[1]
            client_handler = threading.Thread(target=handle_UDP_client, args=(server,port,udp_ip,udp_port))

            try:
                client_handler.start() 
            except KeyboardInterrupt:
                print('Interrupted')
                try:
                    client_handler.stop() 
                    sys.exit(0)
                except SystemExit:
                    os._exit(0)

def create_TCP_listener(host, port, bruteforce):
    #Bruteforce detection for HTTP login page
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((host,port))
    except socket.error, errmsg:
        print errmsg

    server.listen(100)
    print "Listener established for %d TCP port. Honeypot will be tiriggered when connection established." % port
    while True:
        client, addr = server.accept()
        print "Someone tried to reach %d port !!" % port
        print "Possible adversary IP:Port ==> %s:%d" % (addr[0], addr[1])
        client_handler = threading.Thread(target=handle_TCP_client, args=(client,port,bruteforce))

        try:
            client_handler.start() 
        except KeyboardInterrupt:
            print('Interrupted')
            try:
                client_handler.stop() 
                sys.exit(0)
            except SystemExit:
                os._exit(0)

def handle_TCP_client(client_socket, port, bruteforce):

     # print out what the client sends

    #for port scan
    global port_scan_counter

    #try:
    #    (data, addr) = client_socket.recvfrom(1024)
    #except socket.error, ex:
    #    print ex


    #print "[*] Received: %s" % request
    """
    Necessary ports for SIEMENS SCADA
    FTP             20, 21          TCP	
    Telnet	        23	            TCP	
    SMTP            25, 465, 587    TCP	
    DNS	            53	            TCP
    HTTP            80              TCP	
    RFC1006         102             TCP	
    HTTPS	        443	            TCP
    Modbus	        502	            TCP	
    IPSec	        4500	        TCP
    """
    if port == 20 or port == 21:
        #ftp honeypot procedure
        print "ftp port action inc."
        port_scan_counter += 1

    if port == 23:
        #Telnet honeypot procedure
        print "Telnet port action inc."
        port_scan_counter += 1

    if port == 25 or port == 465 or port == 587:
        #SMTP honeypot procedure
        print "SMTP port action inc."
        port_scan_counter += 1

    if port == 53:
        #DNS honeypot procedure
        print "DNS port action inc."
        port_scan_counter += 1
    if not bruteforce:
        if port == 80:
            #HTTP honeypot procedure and HMI interface
            print "HTTP port action inc."
            port_scan_counter += 1

    if port == 102:
        #RFC1006 honeypot procedure
        print "RFC1006  port action inc."  
        port_scan_counter += 1 

    if port == 443:
        #HTTPS honeypot procedure and HMI interface
        print "HTTPS  port action inc."   
        port_scan_counter += 1

    if port == 502:
        #Modbus honeypot procedure
        print "Modbus  port action inc."
        port_scan_counter += 1

    if port == 4500:
        #IPSec honeypot procedure
        print "IPSec  port action inc."
        port_scan_counter += 1

    if port_scan_counter > 8:
        print "Port scan Triggered"
        port_scan_counter = 0

    client_socket.close()

def handle_UDP_client(client_object, port, udp_ip, udp_port):
    # create network discovery detection algorithm
    # create port scan detection algorithm
    # port specific action procedure

    #try:
    #    (data, addr) = client_socket.recvfrom(1024)
    #except socket.error, ex:
    #    print ex
    """
    Necessary ports for SIEMENS SCADA
    DNS	            53	            UDP	
    bootps (DHCP)	67 (server)	    UDP	
    bootpc (DHCP)	68 (client)	    UDP
    TFTP	        69	            UDP	
    NTP	            123	            UDP
    SNMP	        161,162	        UDP	
    ISAKMP	        500	            UDP
    Syslog	        514	            UDP	
    IPSec	        4500	        UDP	
    """
    if port == 53:
        #DNS honeypot procedure
        print "DNS port action inc."

    if port == 67:
        #bootps server honeypot procedure
        print "bootps server port action inc."

    if port == 68:
        #bootps client honeypot procedure
        print "bootps client port action inc."

    if port == 69:
        #TFTP  honeypot procedure
        print "TFTP port action inc."

    if port == 123:
        #NTP  honeypot procedure
        print "NTP port action inc."

    if port == 161 or port == 162:
        #SNMP  honeypot procedure
        print "SNMP port action inc."

    if port == 500:
        #ISAKMP  honeypot procedure
        print "ISAKMP port action inc."

    if port == 514:
        #Syslog  honeypot procedure
        print "Syslog port action inc."

    if port == 4500:
        #IPSec  honeypot procedure
        print "IPSec port action inc."

    #client_object.close()

#END - hONEYPOT MAIN FUNCTIONS

def main_handler(host, port, port_type, eth="ens33", bruteforce=False, shodanDP=False, proactive=False):

    for p in port:
        if port_type == "TCP":
            
            main_listener = threading.Thread(target=create_TCP_listener, args=(host,p, bruteforce))
        
        if port_type == "UDP":
            main_listener = threading.Thread(target=create_UDP_listener, args=(host,p))
    
        main_listener.start()

    #shodan listener
    if shodanDP:
        shodanDP_trigger = threading.Thread(target=shodan_procedure, args=(eth, ))
        shodanDP_trigger.start()

        #shodan listener
    if bruteforce:
        brute_force_trigger= threading.Thread(target=bruteforce_detection_handler)
        brute_force_trigger.start()
    

#generic honeypot creator for specific types. Ex: SCADA
def honeypot_creator(host, honeypot_type):
    
    print "Specified Honeypot Type: %s \n\r" %honeypot_type
    print "Specified Host Address: %s \n\r" %host

    #SCADA type Honeypot
    if honeypot_type == "SCADA":
        print "SIEMENS SCADA profile options."
        print "Source: https://goo.gl/BEpLxZ"
        print "*************************************"
        print "Necessary TCP ports for SIEMENS SCADA"
        print "FTP              20, 21          TCP"	
        print "Telnet           23              TCP"
        print "SMTP             25, 465, 587    TCP"	
        print "DNS              53              TCP"
        print "HTTP             80              TCP"
        print "RFC1006          102             TCP"	
        print "HTTPS            443             TCP"
        print "Modbus           502             TCP"
        print "IPSec            4500            TCP"
        print "*************************************"
        print "Necessary UDP ports for SIEMENS SCADA"
        print "DNS              53              UDP"	
        print "bootps (DHCP)    67 (server)     UDP"
        print "bootpc (DHCP)    68 (client)     UDP"
        print "TFTP             69              UDP"	
        print "NTP              123             UDP"
        print "SNMP             161,162         UDP"	
        print "ISAKMP           500             UDP"
        print "Syslog           514             UDP"	
        print "IPSec            4500            UDP"
        print "*************************************"
        #TCP ports
        port_type = "TCP"
        port = [20, 21, 23, 25, 465, 587, 53, 80, 102, 443, 502, 4500]
        main_handler(host, port, port_type, bruteforce=True)
        #UDP port
        port_type = "UDP"
        port = [53, 67, 68, 69, 123, 161, 162, 500, 514, 4500]
        main_handler(host, port, port_type)

def main():

    host = "192.168.106.129"
    honeypot_type = "SCADA"
    honeypot_creator(host, honeypot_type)
    
main()

