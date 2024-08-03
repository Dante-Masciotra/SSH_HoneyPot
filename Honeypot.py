import argparse
from email.mime.text import MIMEText
import smtplib
import threading
import socket
import sys
import os
import traceback
import logging
import json
import paramiko
from datetime import datetime
from binascii import hexlify
from paramiko.py3compat import b, u, decodebytes

HOST_KEY = paramiko.RSAKey(filename='server.key')
SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Debian GNU/Linux 12"

# Email configuration
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
EMAIL_FROM = 'honeypot.compuwindsor@gmail.com'
EMAIL_TO = ['masciotd@uwindsor.ca', 'wasylykz@uwindsor.ca']
EMAIL_SUBJECT = 'Honeypot Alert'

def send_email_alert(message):
    msg = MIMEText(message)
    msg['From'] = EMAIL_FROM
    msg['To'] = ', '.join(EMAIL_TO)
    msg['Subject'] = EMAIL_SUBJECT

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp_server:
        smtp_server.starttls()
        smtp_server.login(EMAIL_FROM, 'swps rmdd xhmi lqsx')
        smtp_server.send_message(msg)



logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    filename='ssh_honeypot.log')

def handle_cmd(cmd, chan, ip):
    response = ""
    
    if cmd.startswith("ls"):
        response = "users.txt"
    elif cmd.startswith("pwd"):
        response = "/home/root"
    elif cmd.startswith("whoami"):
        response = "root"
    elif cmd.startswith("cat"):
        response = "User Name: Hello\r\nPassword: World"
    elif cmd.startswith("head"):
        response = "User Name: Hello"
    elif cmd.startswith("tail"):   
        response = "Password: World"
    elif cmd.startswith("uname"):
        response = "Linux"
    elif cmd.startswith("ps"):
        response = "PID   TTY          TIME CMD\r\n123   pts/0    00:00:00 bash\r\n124   pts/0    00:00:00 ls\r\n"
    elif cmd.startswith("kill"):
        response = "Process terminated"
    elif cmd.startswith("netstat"):
        response = "Active Internet connections\r\nProto Recv-Q Send-Q Local Address           Foreign Address         State       \r\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      \r\n"
    elif cmd.startswith("ifconfig"):
        response = "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n        inet 192.168.0.100  netmask 255.255.255.0  broadcast 192.168.0.255\r\n        ether 00:0c:29:28:fd:58  txqueuelen 1000  (Ethernet)\r\n        RX packets 0  bytes 0 (0.0 B)\r\n        RX errors 0  dropped 0  overruns 0  frame 0\r\n        TX packets 0  bytes 0 (0.0 B)\r\n        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\r\n"
    elif cmd.startswith("ssh"):
        response = "ssh: connect to host example.com port 22: Connection refused"
    elif cmd.startswith("scp"):
        response = "scp: /path/to/file: No such file or directory"
    elif cmd.startswith("sudo"):
        response = "Password: "
    elif cmd.startswith("wget"):
        response = "200 OK\r\nLength: 524288 (512K) [text/plain]\r\nSaving to: 'index.html'\r\n\r\n100%[===============================================================================>] 524,288     --.-K/s   in 0.1s    \r\n\r\n2024-04-06 12:00:00 (4.00 MB/s) - 'index.html' saved [524288/524288]"
    elif cmd.startswith("curl"):
        response = "<html>\r\n<head>\r\n<title>Example Domain</title>\r\n</head>\r\n<body>\r\n<div>\r\n<h1>Example Domain</h1>\r\n<p>This domain is for use in illustrative examples in documents. You may use this\r\n    domain in literature without prior coordination or asking for permission.</p>\r\n<p><a href='http://www.iana.org/domains/example'>More information...</a></p>\r\n</div>\r\n</body>\r\n</html>\r\n"

    if response != '':
        logging.info('Response from honeypot {} '.format(response))
        response = response + "\r\n"
    chan.send(response)


class BasicSshHoneypot(paramiko.ServerInterface):

    client_ip = None

    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        logging.info('client called check_channel_request ({}): {}'.format(
                    self.client_ip, kind))
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        logging.info('client called get_allowed_auths ({}) with username {}'.format(
                    self.client_ip, username))
        return "publickey,password"   

    def check_auth_password(self, username, password):
        # Accept all passwords as valid by default
        logging.info('new client credentials ({}): username: {}, password: {}'.format(
                    self.client_ip, username, password))
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        command_text = str(command.decode("utf-8"))

        logging.info('client sent command via check_channel_exec_request ({}): {}'.format(
                    self.client_ip, username, command))
        return True


def handle_connection(client, addr):

    client_ip = addr[0]
    
    send_email_alert("Someone Accessed Your Honeypot\n\nIP:({})\nTime: {}".format(client_ip, datetime.now()))
    logging.info('New connection from: {}\nTime: {}'.format(client_ip,datetime.now()))
    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(HOST_KEY)
        transport.local_version = SSH_BANNER # Change banner to appear more convincing
        server = BasicSshHoneypot(client_ip)
        try:
            transport.start_server(server=server)

        except paramiko.SSHException:
            print('*** SSH negotiation failed.')
            raise Exception("SSH negotiation failed")

        # wait for auth
        chan = transport.accept(10)
        if chan is None:
            print('*** No channel (from '+client_ip+').')
            raise Exception("No channel")
        
        chan.settimeout(1000)

        server.event.wait(10)
        if not server.event.is_set():
            logging.info('** Client ({}): never asked for a shell'.format(client_ip))
            raise Exception("No shell request")
     
        try:
            chan.send("Linux Server 6.1.0-15-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.66-1 (2023-12-09) x86_64\r\nThe programs included with the Debian GNU/Linux system are free software;\r\nthe exact distribution terms for each program are described in the\r\nindividual files in /usr/share/doc/*/copyright.\r\n\r\nDebian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent permitted by applicable law.\r\n\r\n")
            run = True
            while run:
                chan.send("$ ")
                command = ""
                commandBuf = ""
                
                while True:
                    transport = chan.recv(1024)    
                    # Handle backspace keypress
                    if transport == b'\x7f':
                        # Remove the last character from the command string
                        command = command[:-1]
                        chan.send(b'\b')  # Move cursor back and erase character
                    elif transport.endswith(b"\r"):
                        chan.send(b"\r\n")
                        commandBuf = ""
                        break
                    elif transport == b'\x1b[D':
                        chan.send(transport)
                        commandBuf += command[len(command)-1]
                        command = command[:-1]
                    else:
                            chan.send(transport)
                            command += transport.decode("utf-8")+commandBuf
                            
                
                command = command.rstrip()
                print(client_ip+"- received:",command)
                logging.info('Command received ({}): {}'.format(client_ip, command))

                if command == "exit":
                    logging.info("Connection closed (via exit command): " + client_ip + "\n")
                    run = False

                else:
                    handle_cmd(command, chan, client_ip)

        except Exception as err:
            print('!!! Exception: {}: {}'.format(err.__class__, err))
            try:
                transport.close()
            except Exception:
                pass

        chan.close()

    except Exception as err:
        print('!!! Exception: {}: {}'.format(err.__class__, err))
        try:
            transport.close()
        except Exception:
            pass


def start_server(port, bind):
    """Init and run the ssh server"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind, port))
    except Exception as err:
        print('*** Bind failed: {}'.format(err))
        traceback.print_exc()
        sys.exit(1)

    threads = []
    while True:
        try:
            sock.listen(100)
            print('Listening for connection ...')
            client, addr = sock.accept()
        except Exception as err:
            print('*** Listen/accept failed: {}'.format(err))
            traceback.print_exc()
        new_thread = threading.Thread(target=handle_connection, args=(client, addr))
        new_thread.start()
        threads.append(new_thread)

    for thread in threads:
        thread.join()


if __name__ == "__main__":
    start_server(2222,'')
