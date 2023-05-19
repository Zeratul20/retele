from scapy.all import DNS, DNSQR, DNSRR, IP, send, sniff, sr1, UDP

bl = open("data/newblacklist.txt", "r")
blacklist = bl.read().splitlines()

interface = 'lo0'
DNS_SERVER_IP = '0.0.0.0'

filter = f"udp port 53 and ip dst {DNS_SERVER_IP}"


def dns_responder(local_ip):
    ip = IP(dst='8.8.8.8')
    transport = UDP(dport = 53)

    # rd = 1 cod de request

    # dns = DNS(rd = 1)

    def forward_dns(orig_pkt):
        print(f"Forwarding: {orig_pkt[DNSQR].qname}")
        transport = UDP(sport=orig_pkt[UDP].sport)
        dns = DNS(rd=1, id=orig_pkt[DNS].id,
                  qd=DNSQR(qname=orig_pkt[DNSQR].qname), verbose=0)
        answer = sr1(ip / transport / dns)
        ans_pkt = IP(dst=orig_pkt[IP].src, src=DNS_SERVER_IP)/UDP(dport=orig_pkt[UDP].sport)/DNS()
        ans_pkt[DNS] = answer[DNS]
        send(ans_pkt, verbose=0)
        return f"Responding to: {orig_pkt[IP].src}"
    
    def get_response(pkt):
        if (DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0):
            if (pkt[DNSQR].qname.decode() in blacklist):
                print(f"Blocked: {pkt[DNSQR].qname.decode()}")
                ip = IP(dst=pkt[IP].src, src=DNS_SERVER_IP)
                transport = UDP(dport=pkt[UDP].sport, sport=53)
                # dns = DNS(id=pkt[DNS].id,ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname, rdata=local_ip))
                dnsrr = DNSRR(rrname=pkt[DNSQR].qname, rdata=local_ip)
                dns = DNS(id=pkt[DNS].id, ancount=1, an=dnsrr)
                spoofed_pkt = ip / transport / dns
                send(spoofed_pkt, verbose=0)
                return f"Blocked: {pkt[DNSQR].qname.decode()}"
            else:
                return forward_dns(pkt)
    return get_response



sniff(filter=filter, prn=dns_responder(DNS_SERVER_IP))
