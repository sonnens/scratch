#!/usr/bin/env python

# A utility to parse & print summaries of pcap files


import sys
import dpkt
import socket


tcp_packets = 0
tcp_connections = {}
tcp_machines = {}
tcp_ports = {}
tcp_attempts = 0

udp_packets = 0
udp_connections = {}
udp_machines = {}
udp_ports = {}

icmp_packets = 0
icmp_connections = []
icmp_sources = set()
icmp_dests = set()

def usage():
	print("Usage: " + sys.argv[0] + " <filename>")

def portstatus(connection):
	"""Tracks TCP ports
	Defaults to 'filtered' by the initial SYN packet
	RST turns 'filtered' in to 'closed'
	ACK turns 'filtered' in to 'OPEN'
	
	Subsequent RST packets will not toggle 'closed'"""

	src, dst, sport, dport, flags = connection
	if ( flags == dpkt.tcp.TH_SYN ):
		if not tcp_ports.get(dst):
			tcp_ports[dst] = { "open": set(), "closed": set(), "filtered": set() }
		if dport not in tcp_ports[dst]["open"] and dport not in tcp_ports[dst]["closed"]:
			tcp_ports[dst]["filtered"].add(dport)

	elif ( flags & dpkt.tcp.TH_RST != 0 ):
		if tcp_ports.get(src):
			if sport in tcp_ports[src]["filtered"]:
				tcp_ports[src]["filtered"].discard(sport)
				tcp_ports[src]["closed"].add(sport)

	elif (flags & dpkt.tcp.TH_ACK):
		if tcp_ports.get(src):
			if sport in tcp_ports[src]["filtered"]:
				tcp_ports[src]["filtered"].discard(sport)
				tcp_ports[src]["open"].add(sport)
		

def udp_portopen(ip, port):
	"""Tracks UDP ports"""
	if not udp_ports.get(ip):
		udp_ports[ip] = { "open": set(), "closed": set() }
	udp_ports[ip]["open"].add(port)

def udp_portclose(ip, port):
	if udp_ports.get(ip):
		udp_ports[ip]["open"].discard(port)
		udp_ports[ip]["closed"].add(port)

def process_tcp(eth):
	"""Processes a TCP packet
	Tracks streams based on source IP:dest IP & source port:dest port pairs
	Tracks data on a per-stream basis
	"""
	global tcp_attempts
	ip = eth.data
	tcp = eth.data.data

	flow = ((ip.src,ip.dst), (tcp.sport, tcp.dport))
	replyflow = ((ip.dst,ip.src), (tcp.dport, tcp.sport))
	if flow not in tcp_connections.keys() and replyflow not in tcp_connections.keys():
		src = socket.inet_ntoa(ip.src)
		dst = socket.inet_ntoa(ip.dst)
		tcp_connections[flow] = {"count": 1, "initial": {"src":src, "dst":dst, "sport":tcp.sport, "dport":tcp.dport}}
	elif flow in tcp_connections.keys():
		tcp_connections[flow]["count"] += 1
	else:
		tcp_connections[replyflow]["count"] += 1

	# track new TCP connection attempts	
	if ( tcp.flags == dpkt.tcp.TH_SYN ):
		tcp_attempts += 1

	# Explicitly not recording data on replies, with the assumption that it has the potential
	#   to be massive
	if (len(tcp.data) > 0 and tcp_connections.get(flow)):
		if (tcp_connections[flow].get("data")):
			tcp_connections[flow]["data"] = tcp_connections[flow]["data"] + tcp.data
		else:
			tcp_connections[flow]["data"] = tcp.data

	portstatus((ip.src, ip.dst, tcp.sport, tcp.dport, tcp.flags))

def process_udp(eth):
	"""Processes a UDP packet
	Tracks streams based on source IP:dest IP & source port:dest port pairs
	Tries to process DNS data if the initial dest port is 53
	"""
	ip = eth.data
	udp = ip.data

	flow = ((ip.src,ip.dst), (udp.sport, udp.dport))
	replyflow = ((ip.dst,ip.src), (udp.dport, udp.sport))

	if flow not in udp_connections.keys() and replyflow not in udp_connections.keys():
		src = socket.inet_ntoa(ip.src)
		dst = socket.inet_ntoa(ip.dst)
		udp_connections[flow] = {"count": 1, "initial": {"src":src, "dst":dst, "sport":udp.sport, "dport": udp.dport}}
		# add the port to a list of potentially open ports, and the ICMP UNREACH_PORT packet can remove it
		udp_portopen(ip.dst, udp.dport)
	elif flow in udp_connections.keys():
		udp_connections[flow]["count"] += 1
	else:
		udp_connections[replyflow]["count"] += 1

	if (len(udp.data) > 0 and (udp.dport == 53 or udp.sport == 53)):
		try:
			if udp_connections.get(flow):
				direction = flow
			elif udp_connections.get(replyflow):
				direction = replyflow
			data = dpkt.dns.DNS(udp.data)
			if udp_connections[direction].get("data"):
				udp_connections[direction]["data"].append(data)
			else:
				udp_connections[direction]["data"] = [data]
		except:
			# Just continue if we fail to process DNS data in this stream
			return

def process_icmp(eth):
	"""Processes an ICMP packet
	Decodes some but not all ICMP types & codes. Gives numerical values otherwise
	ICMP port unreachable flips the state of UDP ports if stored
	"""
	ip = eth.data
	icmp = ip.data
	t = icmp.type
	code = icmp.code
	if t  == dpkt.icmp.ICMP_ECHOREPLY:
		t = "Echo Reply (0)"
	elif t == dpkt.icmp.ICMP_ECHO:
		t = "Echo Request (8)"
	elif t == dpkt.icmp.ICMP_TIMEXCEED:
		t = "Time Exceeded (11)"
		if (code == dpkt.icmp.ICMP_TIMEXCEED_INTRANS):
			code = "TTL expired (0)"
		else:
			code = "Fragment reassembly time exceeded (1)"
	elif t == dpkt.icmp.ICMP_UNREACH:
		t = "Unreachable (3)"
		if code == dpkt.icmp.ICMP_UNREACH_PORT:
			code = "Unreachable Port (3)"
			dip = icmp.data.data
			dudp = dip.data
			udp_portclose(ip.src, dudp.dport)
	icmp_connections.append((ip.src, ip.dst, t, code))
	icmp_sources.add(socket.inet_ntoa(ip.src))
	icmp_dests.add(socket.inet_ntoa(ip.dst))

def print_dns(connection, prepend):
	"""Print DNS data.
	Pull queries from the initial query
	Print all resolution data in the response packet
	"""
	if connection.get("data"):
		if connection["initial"]["dport"] == 53:
			print prepend + "DNS:"
			for data in connection["data"]:
				for query in data.qd:
					# don't print the query data that accompanies a response
					if data.op & 0x8000 == 0:
						print (prepend * 2) + "Query: " + str(query.name)
				for res in data.an:
					if res.type == dpkt.dns.DNS_A:
						print (prepend * 3) + "Answer (A):     " + socket.inet_ntoa(res.rdata)
					elif res.type == dpkt.dns.DNS_NS:
						print (prepend * 3) + "Answer (NS):    " + res.nsname
					elif res.type == dpkt.dns.DNS_CNAME:
						print (prepend * 3) + "Answer (CNAME): " + res.cname
					elif res.type == dpkt.dns.DNS_SOA:
						print (prepend * 3) + "Answer (SOA):   " + str(res.minimum)
					elif res.type == dpkt.dns.DNS_PTR:
						print (prepend * 3) + "Answer (PTR):   " + res.ptrname
					elif res.type == dpkt.dns.DNS_HINFO:
						print (prepend * 3) + "Answer (HINFO): " + res.txt
					elif res.type == dpkt.dns.DNS_MX:
						print (prepend * 3) + "Answer (MX):    " + res.mxname
					elif res.type == dpkt.dns.DNS_TXT:
						print (prepend * 3) + "Answer (TXT):   " + res.txt
					elif res.type == dpkt.dns.DNS_AAAA:
						print (prepend * 3) + "Answer (AAAA):  " + socket.inet_ntop(socket.AF_INET6, res.rdata)
					elif res.type == dpkt.dns.DNS_SRV:
						print (prepend * 3) + "Answer (SRV):   " + res.srvname

def print_http_ftp(connection, prepend):
	"""Print HTTP and FTP sender data.
	Does not print server payloads
	"""
	if connection.get("data"):
		if connection["initial"]["dport"]  == 80:
			http = dpkt.http.Request(connection["data"])
			print prepend + "HTTP " + http.method + " " + http.uri + "\n"
		elif connection["initial"]["dport"]  == 21:
			print prepend + "FTP SESSION:\n" + 2*prepend + ('\n' + 2*prepend).join(connection["data"].split('\n'))

def print_conn(connections, conn_type, prefix):
	"""Print 2-way connection data for TCP & UDP
	Initiator is assumed by first packet recieved on this source:dest ip&port pairs
	"""
	for cxn in connections:
		src = connections[cxn]["initial"]["src"]
		dst = connections[cxn]["initial"]["dst"]
		sport = str(connections[cxn]["initial"]["sport"])
		dport = str(connections[cxn]["initial"]["dport"])
		count = str(connections[cxn]["count"])
		print prefix + src + ":" + sport + " -> " + dst + ":" + dport

		# Print HTTP & FTP on TCP packets
		if (conn_type == "tcp"):
			print_http_ftp(connections[cxn], 2*prefix)
		
		# Attempt to print DNS lookups on udp packets
		if (conn_type == "udp"):
			print_dns(connections[cxn], 2*prefix)

def print_icmp(connections, prefix):
	"""Print ICMP data
	Does not attempt to ascertain why a packet was sent (ie, does not give visibility
		in to whether a ping reply was a result of a ping)
	Also lists & rank orders ICMP packet destinations
	"""
	print "ICMP sources: " + ", ".join(list(icmp_sources))
	print "ICMP destinations: " + ", ".join(list(icmp_dests))
	print "\n"

	targets = {}
	for connection in connections:
		src, dst, t, code = connection
		if not targets.get(dst):
			targets[dst] = 1
		else:
			targets[dst] += 1
		print prefix + socket.inet_ntoa(src) + " -> " + socket.inet_ntoa(dst) + " (type: " + str(t) + " code: " + str(code) + ")"
	popular = sorted (targets.items(), key=lambda x: x[1] )[::-1]
	print "\n"
	print prefix + "Most frequent ICMP destinations:"
	for item in popular:
		print 2*prefix + socket.inet_ntoa(item[0]) + ": (" + str(item[1]) + " packets)"


def printports(machines, t, prefix):
	mkeys = machines.keys()
	keys = machines[mkeys[0]].keys()
	for key in keys:
		print prefix + t.upper() + " " + key + ":"
		for mach in machines:
			if len(machines[mach][key]) > 0:
				print 2*prefix + socket.inet_ntoa(mach) + ":"
				for i in sorted(list(machines[mach][key])):
					print 3*prefix + str(i)
		print "\n"
	
if __name__ == "__main__":
	if len(sys.argv) < 2:
		usage()
		sys.exit(1)


	f = open(sys.argv[1], 'r')
	pcap = dpkt.pcap.Reader(f)
	for ts, buf in pcap:
		eth = dpkt.ethernet.Ethernet(buf)
		ip = eth.data
		if type(eth.data.data) == dpkt.tcp.TCP:
			tcp_packets += 1
			process_tcp(eth)
		elif type(ip.data) == dpkt.udp.UDP:
			udp_packets += 1
			process_udp(eth)
		elif type(eth.data.data) == dpkt.icmp.ICMP:
			icmp_packets += 1
			process_icmp(eth)


	print "############# TCP ##############"
	print "\n"
	print "TCP Total connection attempts: " + str(tcp_attempts)
	print "\n"
	printports(tcp_ports, 'tcp', ' ')

	print "TCP packets (Total " + str(tcp_packets) + "):\n"
	print_conn(tcp_connections, "tcp", ' ')

	print "\n"
	print "############# UDP ##############"
	printports(udp_ports, 'udp', ' ')

	print "UDP packets (Total " + str(udp_packets) + "):\n"
	print_conn(udp_connections, "udp", ' ')
	print "\n"

	print "############# ICMP #############"
	print "\n"
	print "ICMP packets: (count: " + str(icmp_packets) + ")\n"
	print_icmp(icmp_connections, ' ')

