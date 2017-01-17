import socket
import sys

""""
Send message via UDP
How to use?
    sudo python sock_sender.py  <destination_ip>
    sudo python sendeth.py  10.0.0.18
"""

MESSAGE = "Checking connectivity"
if len(sys.argv) < 2:
    print "No destination IP provided, using localhost"
    UDP_IP = "127.0.0.1"
else:
    UDP_IP = sys.argv[1]
print("UDP destination IP:", UDP_IP)
UDP_PORT = 5005

# print("UDP target port:", UDP_PORT)
# print("message:", MESSAGE)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(bytes(MESSAGE), (UDP_IP, UDP_PORT))
