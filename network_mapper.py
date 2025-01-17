import socket
from scapy.all import ARP, Ether, srp
import networkx as nx
import matplotlib.pyplot as plt

def get_local_ip():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip

def get_network_prefix(local_ip):
    return '.'.join(local_ip.split('.')[:-1]) + '.'

def scan_network(network_prefix):
    print("Scanning the network...")
    devices = []
    arp_request = ARP(pdst=network_prefix + "1/24")
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp_request
    result = srp(packet, timeout=2, verbose=0)[0]

    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

def map_network(devices):
    G = nx.Graph()
    
    for device in devices:
        G.add_node(device['ip'], label=device['mac'])

    local_ip = get_local_ip()
    for device in devices:
        if device['ip'] != local_ip:
            G.add_edge(local_ip, device['ip'])

    pos = nx.spring_layout(G)
    labels = nx.get_node_attributes(G, 'label')
    nx.draw(G, pos, with_labels=True, node_size=3000, node_color="lightblue", font_size=10, font_weight="bold")
    nx.draw_networkx_labels(G, pos, labels=labels)
    plt.title("Network Map")
    plt.show()

def main():
    local_ip = get_local_ip()
    network_prefix = get_network_prefix(local_ip)
    devices = scan_network(network_prefix)
    map_network(devices)

if __name__ == "__main__":
    main()