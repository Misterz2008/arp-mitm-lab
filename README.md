# arp-mitm-lab

A minimal man-in-the-middle between two hosts on the same subnet: **ARP
poisoning** to steal the traffic, **iptables REDIRECT** to hand it to a local
socket, and a **plain Python proxy** to relay it. About 130 lines in `mitm.py`,
plus the 30-line version it grew out of in `original.py`.

```
client ──► "10.0.0.3 is at my MAC" ──► me ──► relayed TCP ──► server
```

## The part that actually stops you

ARP poisoning on its own gets the frames to your network card, and then nothing
happens. The frame still carries the server's IP address, the kernel sees
**transit traffic** rather than a local destination, and no local socket ever
sees it. You can poison perfectly and still accept zero connections.

The fix is a NAT rule that fires before the routing decision:

```bash
iptables -t nat -A PREROUTING -s 10.0.0.2 -d 10.0.0.3 -p tcp \
         --dport 31337 -j REDIRECT --to-ports 31337
```

`REDIRECT` rewrites the destination to the local machine, so the packet lands
on the listening socket instead of being dropped or blindly forwarded.

Second thing that bites: **the ARP cache heals**. One spoofed packet holds for
a few seconds at most, so poisoning has to be a loop, not a one-shot.

## Usage

```bash
pip install -r requirements.txt
sudo python3 mitm.py --iface eth0 --client 10.0.0.2 --server 10.0.0.3 --port 31337
```

| option | meaning |
|---|---|
| `--iface` | interface facing the victim |
| `--client` / `--server` | the two ends, IPv4 |
| `--port` | TCP port to intercept |
| `--inject` | optional text sent upstream on every new connection |
| `--interval` | seconds between poison packets, default `1.0` |

Ctrl-C removes the iptables rule and restores the real ARP mappings, so the
network keeps working afterwards.

## History

The first version was about 30 lines and it worked: two hardcoded addresses, an
ARP spoof in each direction, a proxy on the intercepted port, and a payload sent
*after* the server asked for a command. It is in
[`original.py`](original.py), unedited.

`mitm.py` is the same idea with the interfaces filed off — addresses and port as
arguments, the `REDIRECT` rule added and removed automatically, ARP restored on
exit. Nothing in the logic is smarter; there is just less to remember when you
come back to it in a month.

One difference worth knowing: the original injected at a specific point in the
protocol, after the command prompt. `mitm.py --inject` fires right after the
connection is established — that is the limitation listed below.

## Limitations

- TCP only, one thread per connection, no bulk throughput.
- `--inject` fires right after connecting. A payload that must arrive *after*
  an auth exchange needs a protocol-aware hook.
- No TLS interception — this is about getting the traffic, not reading it.

## Legal and intended use

This is a dual-use tool. Publishing it and reading it is legal; pointing it at a
network you do not control is not. In Poland that is art. 267 k.k. (unauthorised
access to information), and similar provisions exist across the EU under
Directive 2013/40/EU.

So: run it inside your own lab, or with written permission from whoever owns the
network. Every address in the examples is an RFC 1918 private address from a lab
(`10.0.0.0/24`), there is no target list, and nothing here is aimed at a
third party.

Two things were deliberately left out of the published code: the concrete
payload (replaced with a placeholder in `original.py`), and any target-specific
detail. What is left is the technique, which is taught in every entry-level
network security course.
