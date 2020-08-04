import sys
import os
from scapy.all import sr1, IP, ICMP, traceroute
if len(sys.argv) !=2:
    sys.exit('Less aguments supplied: expected 1 text file with domains')

def performScan(host):
    # ttl = 1
    # while 1:
    #     p = sr1(IP(dst=host, tt1 = ttl)/ICMP(id=os.getpid()), verbose = 0)
    #     if p[ICMP].type == 11 and p[ICMP].code == 0:
    #         print ttl, '-->',p.src
    #         ttl =+ 1
    #     elif p[ICMP].type == 0:
    #         print ttl,'-->',p.src
    #         break
    try:
        for i in range(1,28):
            pkt = IP(dst=host.strip(), ttl=i)/UDP(dport=33434)
            reply = sr1(pkt, verbose=0)
            if reply is None:
                break
            elif reply.type == 3:
                print 'Done', reply.src
            else:
                print "%d hops away: "%i, reply.src
    except Exception ,e :
        try:
            traceroute(host.strip())
        except Exception,e:
            print("An err occurred: Please check your proxy settings")


if __name__ == '__main__':
    with open(sys.argv[1]) as file:
        for host in file.readlines():
            print 'Scanning',host
            performScan(host)
            
