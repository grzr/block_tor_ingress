import jinja2
import requests
import ipaddress
from typing import List

BASE_URL = "https://lists.fissionrelays.net/tor/"

TEMPLATE = """
resource "google_compute_firewall_policy_rule" "block_ingress_from_tor_exit_node_{{ counter }}" {
  firewall_policy = google_compute_firewall_policy.block_tor_traffic.id
  description = "Block Ingress from TOR exit nodes IPs [{{ counter }}/{{ total }}]"
  priority = {{ priority }}
  enable_logging = true
  action = "deny"
  direction = "INGRESS"
  disabled = false
  match {
    layer4_configs {
      ip_protocol = "all"
    }
    src_ip_ranges = [
    {% for ip in ip_ranges %}"{{ ip }}",
    {% endfor %}]
  }
}
"""
IPs = List[str]


def fetch_ips(source: str) -> IPs:
    return requests.get(BASE_URL + source, verify=False).text.split('\n')


def format_ips(ips: IPs) -> IPs:
    u = list(set(ip for ip in ips if ip))
    u.sort()
    return u


def split_to_buckets(array, bucket_size):
    k, m = divmod(len(array), bucket_size)
    buckets_count = k if m == 0 else k + 1
    return list(array[i * bucket_size:i * bucket_size + bucket_size] for i in range(buckets_count))


subnet_sizes = {
    26: 64,
    27: 32,
    28: 16,
    29: 8,
    30: 4,
    31: 2,
}


def ipv_to_blocks(exits_ipv: IPs, factory) -> IPs:
    class Subnet(object):
        def __init__(self, ip):
            self.subnet = ip
            self.ips = []

    new_subnets = []
    groupped_ips = []
    for ip in exits_ipv:
        if ip in groupped_ips:
            continue
        for size, expectedIPsCount in subnet_sizes.items():
            try:
                s = Subnet(ip=factory(ip + '/' + str(size)))
                for iip in exits_ipv:
                    if iip in groupped_ips:
                        continue
                    iis = factory(iip)
                    if s.subnet.supernet_of(iis):
                        s.ips.append(iip)
                if expectedIPsCount == len(s.ips):
                    new_subnets.append(s.subnet)
                    groupped_ips.extend(s.ips)
                    break
            except ValueError:
                # has host bits set
                continue
    # return new subnets + ip outside new subnets
    new_subnets.extend(list(ip for ip in exits_ipv if ip not in groupped_ips))
    return new_subnets


exits_ipv6 = format_ips(fetch_ips('exits-ipv6.txt'))
exits_ipv6_blocks = ipv_to_blocks(exits_ipv6, ipaddress.IPv6Network)
ipv6_buckets = split_to_buckets(exits_ipv6_blocks, 256)
print('🌿', len(exits_ipv6), [len(b) for b in ipv6_buckets], sum(len(b) for b in ipv6_buckets))

exits_ipv4 = format_ips(fetch_ips('exits-ipv4.txt'))
exits_ipv4_blocks = ipv_to_blocks(exits_ipv4, ipaddress.IPv4Network)
ipv4_buckets = split_to_buckets(exits_ipv4_blocks, 256)
print('💕', len(exits_ipv4), [len(b) for b in ipv4_buckets], sum(len(b) for b in ipv4_buckets))

with open('auto_generated_firewall_policy_rules.tf', 'w') as f:
    exits_buckets = []
    exits_buckets.extend(ipv4_buckets)
    exits_buckets.extend(ipv6_buckets)
    for i in range(len(exits_buckets)):
        t = jinja2.Template(TEMPLATE)
        c = t.render(counter=i + 1, total=len(exits_buckets), ip_ranges=exits_buckets[i], priority=9000 + i)
        f.write(c)
