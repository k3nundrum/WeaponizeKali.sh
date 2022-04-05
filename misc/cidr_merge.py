#!/usr/bin/env python3

"""
Merge standalone IPs into CIDRs.

Example:
$ cat ~/ws/enum/adidns.csv | awk -F, '{print $3}' > ip.lst
$ cidr_merge.py | sort -u -t'.' -k1,1n -k2,2n -k3,3n -k4,4n | grep -e '^192' -e '^172' -e '^10'
"""

import netaddr

iplst = []
with open('ip.lst', 'r') as fd:
	for line in fd:
		ip = line.rstrip('\n')
		try:
			iplst.append(netaddr.IPNetwork(f'{ip}/24'))
		except netaddr.core.AddrFormatError:
			pass

for net in netaddr.cidr_merge(iplst):
	print(str(net))
