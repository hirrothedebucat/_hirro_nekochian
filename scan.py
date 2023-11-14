from scapy.all import *
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import TCP, IP
from optparse import OptionParser
import threading
import ipaddress


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


def parse_ip(targets):
    _split = targets.split('-')
    first_ip = _split[0]
    ip_split = first_ip.split('.')
    ipv4 = range(int(ip_split[3]), int(_split[1])+1)
    addr = [ip_split[0]+'.'+ip_split[1]+'.'+ip_split[2]+'.'+str(p) for p in ipv4]
    return addr


def arp_scan(ip):
    arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    ans, _ = srp(arp_req, timeout=1, verbose=0)
    result = []
    for _, received in ans:
        result.append({'IP': received.psrc, 'MAC': received.hwsrc})
    print(f"当前活动主机: {result}")
    return result


def tcp_port_scan(host, start_port=0, end_port=100):
    ip = host['IP']
    open_ports = []
    # 使用循环遍历指定的端口范围
    for port in range(start_port, end_port + 1):
        pkt = IP(dst=ip) / TCP(dport=port, flags='S')
        resp = sr1(pkt, timeout=1, verbose=0)
        print(port)  # 监控扫描进程
        # 检查响应对象
        if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:  # 0x12 是 SYN-ACK 的十六进制表示
            print(f"{port} is available")  # 报告扫描成功的端口
            open_ports.append(port)
    print(f"主机{ip}处于listen状态的端口: {open_ports}")
    return open_ports


def scan_lan(addrlist):
    # 扫描端口为I/O密集型任务，使用多线程
    try:
        hosts = arp_scan(addrlist)
        threads = []
        for host in hosts:
            ip = host['IP']
            print(f"\n扫描{ip}中...")
            t = threading.Thread(target=tcp_port_scan, args=(host,))
            threads.append(t)
            t.start()
        for item in threads:
            item.join()
    except Exception:
        exit(1)


if __name__ == "__main__":
    network_info = get_network_info()
    local_ip = network_info['local_ip']
    subnet_mask = "255.255.255.128"
    valid_ips = calculate_ip_range(local_ip, subnet_mask)
    print(f"\n\n本机IP网段的有效IP范围: {valid_ips[0]} - {valid_ips[-1]}\n")
    parser = OptionParser()
    parser.add_option("-a", "--addr", dest="address", help="--> input(for example): 218.192.160.1-126")
    (options, args) = parser.parse_args()
    if options.address:
        addr_list = parse_ip(options.address)
        scan_lan(addr_list)
    else:
        parser.print_help()
