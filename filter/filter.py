from scapy.all import *

def get_local_macs():
    """
    Get the local mac address of all connected devices 
    """

    tmp = set()
    ans, uans = arping("192.168.0.0/24", verbose=0)

    for s, r, in ans:
        tmp.add(r[Ether].src)

    return tmp
