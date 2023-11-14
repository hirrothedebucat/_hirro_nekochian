import socket
import ipaddress
from scapy.layers.l2 import Ether, ARP, srp
from scapy.layers.inet import TCP, IP, sr1


def get_network_info():
    # 获取本地主机名和IP地址
    hostname = socket.gethostname()
    local_ip1 = socket.gethostbyname(hostname)

    # 获取网络接口信息
    interfaces = socket.if_nameindex()

    # 获取默认网关
    default_gateway = None
    for interface in interfaces:
        if interface[1] == 2:
            default_gateway = socket.if_indextoname(interface[0])
            break

    return {
        'hostname': hostname,
        'local_ip': local_ip1,
        'default_gateway': default_gateway,
        'interfaces': interfaces
    }


def calculate_ip_range(local_ip1, subnet_mask1):
    # 计算有效IP范围
    network = ipaddress.IPv4Network(f'{local_ip1}/{subnet_mask1}', strict=False)
    return list(network.hosts())

# 获取局域网内的所有活动主机


def arp_scan(ip):
    arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    ans, _ = srp(arp_req, timeout=1, verbose=0)
    result = []
    for _, received in ans:
        result.append({'IP': received.psrc, 'MAC': received.hwsrc})
    print(f"当前活动主机:{result}")
    return result

# 扫描指定 IP 地址的 TCP 端口


def tcp_port_scan(ip, start_port=0, end_port=65535):
    open_ports = []

    # 使用循环遍历指定的端口范围
    for port in range(start_port, end_port + 1):
        pkt = IP(dst=ip) / TCP(dport=port, flags='S')
        resp = sr1(pkt, timeout=1, verbose=0)
        # 检查响应对象
        if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:  # 0x12 是 SYN-ACK 的十六进制表示
            print(f"{port} is available")
            open_ports.append(port)
        else:
            print(port)

    return open_ports


# 扫描局域网内所有活动主机的 TCP 端口


def scan_lan(ip_net):
    hosts = arp_scan(ip_net)
    for host in hosts:
        ip = host['IP']
        print(f"\n扫描{ip}中...")
        open_ports = tcp_port_scan(ip)
        print(f"主机{ip}处于listen状态的端口: {open_ports}")


if __name__ == "__main__":
    network_info = get_network_info()
    local_ip = network_info['local_ip']

    # 这里假设掩码为 255.255.255.128，你可以根据实际情况修改 subnet_mask
    subnet_mask = "255.255.255.128"

    valid_ips = calculate_ip_range(local_ip, subnet_mask)
    print(f"\n\n本机IP网段的有效IP范围: {valid_ips[0]} - {valid_ips[-1]}")
    ip_range = '218.192.160.1/25'
    scan_lan(local_ip)
