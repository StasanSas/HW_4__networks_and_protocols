import time
from ipaddress import ip_address, IPv4Address, IPv6Address
from argparse import ArgumentParser, Namespace

import ipwhois
from scapy.layers.inet import IP, TCP, UDP, ICMP, sr1
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest


def parse_in_dict_arguments(arguments):
    return {"timeout": arguments.timeout, "port": arguments.port,
            "number_requests": arguments.number_requests,
            "view_autonomous_system": arguments.view_autonomous_system,
            "ip": arguments.ip[0], "protocol": arguments.protocol[0]}


def get_type_internet_protocol_protocol(ip):
    ip_protocol = ip_address(ip)
    if isinstance(ip_protocol, IPv4Address):
        return "ipv4"
    if isinstance(ip_protocol, IPv6Address):
        return "ipv6"


def try_send_package_and_give_ip_which_stop(packet, arguments, number):
    start = time.time()
    response = sr1(packet, timeout=arguments["timeout"], verbose=False)
    time_ms = ((time.time() - start) * 1000) // 1
    if not response:
        print(f"{number} *")
        return None
    response_ip = response.src
    if arguments["view_autonomous_system"]:
        print(f"{number} {response_ip} {time_ms} ms {get_autonomous_system(response_ip)}")
    else:
        print(f"{number} {response_ip} {time_ms} ms")
    return response_ip


def get_autonomous_system(ip):
    try:
        return ipwhois.IPWhois(ip).lookup_rdap()['asn']
    except ipwhois.IPDefinedError:
        return '*'


parser = ArgumentParser()
parser.add_argument("-t", "--timeout", type=int, default=2)
parser.add_argument("-p", "--port", type=int)
parser.add_argument("-n", "--number_requests", type=int, default=256)
parser.add_argument("-v", "--view_autonomous_system")
parser.add_argument("ip", nargs=1)
parser.add_argument("protocol", nargs=1, choices=["tcp", "udp", "icmp"])

all_args: Namespace = parser.parse_args()
arguments = parse_in_dict_arguments(all_args)
packet_func = \
    {
        ("ipv4", "udp"): lambda ip, ttl, port: IP(dst=ip, ttl=ttl) / UDP(dport=port),
        ("ipv4", "tcp"): lambda ip, ttl, port: IP(dst=ip, ttl=ttl) / TCP(dport=port),
        ("ipv4", "icmp"): lambda ip, ttl, port: IP(dst=ip, ttl=ttl) / ICMP(),
        ("ipv6", "udp"): lambda ip, ttl, port: IPv6(dst=ip, hlim=ttl) / UDP(dport=port),
        ("ipv6", "tcp"): lambda ip, ttl, port: IPv6(dst=ip, hlim=ttl) / TCP(dport=port),
        ("ipv6", "icmp"): lambda ip, ttl, port: IPv6(dst=ip, hlim=ttl) / ICMPv6EchoRequest(),
    }
internet_protocol = get_type_internet_protocol_protocol(arguments["ip"])

ttl = 1
while ttl < arguments["number_requests"]:
    func_for_create_packet = packet_func[(internet_protocol, arguments["protocol"])]
    packet = func_for_create_packet(arguments["ip"], ttl, arguments["port"])
    response_ip = try_send_package_and_give_ip_which_stop(packet, arguments, ttl)
    if response_ip == arguments["ip"]:
        break
    ttl += 1
