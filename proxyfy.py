import sys
import socket
import threading

def receive_from(connection):
    buffer = ""
    
    connection.settimeout(5)
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except:
        pass
    
    return buffer

def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    
    #remote host connection
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host,remote_port))
    
    if receive_first:
        remote_buffer = receive_from(remote_socket)
        print remote_buffer
        
        #response handler needed 
        '''
        x. Inside this function,you can modify the packet contents,
        perform fuzzing tasks, test for authentication
        issues, or whatever else your heart desires.
        '''
        
        if len(remote_buffer):
            print "[<==] Sending %d bytes to localhost." % len(remote_buffer)
            client_socket.send(remote_buffer)
        
    while True:
        local_buffer = receive_from(client_socket)
        
        if len(local_buffer):
            print "[==>] Received %d bytes from localhost." % len(local_buffer)
            print local_buffer
            
            #request handler needed
            '''
            x. Inside this function,you can modify the packet contents,
            perform fuzzing tasks, test for authentication
            issues, or whatever else your heart desires.
            '''            
            
            remote_socket.send(local_buffer)
            print "[==>] Sent to remote."
            
        remote_buffer = receive_from(remote_socket)
            
        if len(remote_buffer):
            print "[<==] Received %d bytes from remote host." % len(remote_buffer)
            print remote_buffer
            
            #response handler needed 
            '''
            x. Inside this function,you can modify the packet contents,
            perform fuzzing tasks, test for authentication
            issues, or whatever else your heart desires.
            '''
            
            client_socket.send(remote_buffer)
            print "[<==] Sent to localhost."
            
        if not len(remote_buffer) or not len(local_buffer):
            client_socket.close()
            remote_socket.close()
            print "No more data. Closing connections."
            
            break

def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
    #server create
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        server.bind((local_host,local_port))
    except:
        print "!! Server binding unsuccesfull at %s:%d" %(local_host, local_port)
        print "!! check for parameters or permissions."
        sys.exit(0)
    
    print "[*] Listening on %s:%d" % (local_host,local_port)

    server.listen(5)
    
    while True:
        client_socket, addr = server.accept()        
        print "Received incoming connection from %s:%d" % (addr[0], addr[1])
        
        #make some thread job here ^^
        proxy_thread = threading.Thread(target=proxy_handler, args=(client_socket, remote_host, remote_port, receive_first))
        proxy_thread.start()


def main():
    #localhost, localport, remotehost, remoteport, receivefirst
    if len(sys.argv[1:]) != 5:
        print "Usage> ./proxyfy.py [localhost][localport][remotehost][remoteport][receive_first]"
        print "Example usage: ./proxyfy.py 127.0.0.1 6565 test.rebex.net 21 True"
        sys.exit(0)
        
    #local listening parameters
    local_host = sys.argv[1]
    local_port = int(sys.argv[2])

    #remote target
    remote_host= sys.argv[3]
    remote_port= int(sys.argv[4])
    
    #for some banner issues
    receive_first = sys.argv[5]
    
    if "True" in receive_first:
        receive_first = True
    else:
        receive_first = False
        
    print "Given parameters are:"
    print sys.argv[1:]

    server_loop(local_host, local_port, remote_host, remote_port, receive_first)

main()


    