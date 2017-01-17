import socket
import sys
""""
Send raw Ethernet packet on interface.
How to use?
    sudo python sendeth.py  <listening_ip>
"""

if len(sys.argv) < 2:
    print "No destination IP provided, using localhost"
    UDP_IP = "127.0.0.1"
else:
    UDP_IP = sys.argv[1]
print("UDP listening IP:", UDP_IP)
UDP_PORT = 5005

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

data, addr = sock.recvfrom(1024)
print "received message:", data
