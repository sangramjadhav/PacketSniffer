from scapy.all import *
from optparse import OptionParser
from datetime import datetime

#  
#  Simple Packet Sniffer with support for BPF style filter using Scapy
#  It can save packets to pcap file.
#  It also provides option to limit capture upto given packets
#  
class PacketSniffer:
	
	def __init__(self,options):
		
		self.options = options
	
		self.pktCount = self.options.pktCount
		
		self.filter = self.options.filter
		
		if not self.options.pcap:
			self.pcap = "tmp.pcap"
		else:
			self.pcap = self.options.pcap
		
		if not self.options.device:
			print "No device specified. Will sniff on all device"
		else:
			self.device = self.options.device
		
		self.pcapWriter = PcapWriter(self.pcap, append=True, sync=True)

	def main(self):
		# Start sniffing some packets
		#sniff(filter=filter, prn=lambda x: x.summary(), count=count, store=0)
		if hasattr(self, "device"):
			sniff(iface=self.device, filter=self.filter, prn=self.savePacket, count=self.pktCount, store=0)
		else:
			sniff(filter=self.filter, prn=self.savePacket, count=self.pktCount, store=0)
	
	def savePacket(self,p):
		print self.formatPacket(p)
		self.pcapWriter.write(p)
	
	def cleanPayload(self,p):
		p = str(p)
		# Clean up packet payload from scapy output
		return p.split('Raw')[0].split("Padding")[0].replace('|','\n').strip('<')\
			.strip('bound method Ether.show of ').replace('>','').replace('[<','[')\
			.replace('\n<','<').replace('<','\n')
	
	def formatPacket(self,rawPacket):
		try:
			l2 = rawPacket.summary().split("/")[0].strip()
			l3 = rawPacket.summary().split("/")[1].strip()
			srcIP, dstIP, L7protocol, size, ttl, srcMAC, dstMAC, L4protocol, srcPort, dstPort, payload =\
				"---","---","---","---","---","---","---","---","---","---","---"
			payload = self.cleanPayload(rawPacket[0].show)
			if rawPacket.haslayer(Ether):
				srcMAC = rawPacket[0][0].src
				dstMAC = rawPacket[0][0].dst
			elif rawPacket.haslayer(Dot3):
				srcMAC = rawPacket[0][0].src
			 	srcIP = rawPacket[0][0].src
			 	dstMAC = rawPacket[0][0].dst
			 	dstIP = rawPacket[0][0].dst
			 	if rawPacket.haslayer(STP):
			 		L7protocol = 'STP'
				 	payload = self.cleanPayload(rawPacket[STP].show)
			if rawPacket.haslayer(Dot1Q):
				l3 = rawPacket.summary().split("/")[2].strip()
				l4 = rawPacket.summary().split("/")[3].strip().split(" ")[0]
			if rawPacket.haslayer(ARP):
			 	srcMAC = rawPacket[0][0].src
			 	srcIP = rawPacket[0][0].src
			 	dstMAC = rawPacket[0][0].dst
			 	dstIP = rawPacket[0][0].dst
			 	L7protocol = 'ARP'
			 	payload = self.cleanPayload(rawPacket[0].show)
			# else if rawPacket.haslayer(CDP):
			# 	#dostuff
			#else if rawPacket.haslayer(DHCP):
			# 	#dostuff
			# else if rawPacket.haslayer(DHCPv6):
			# 	#dostuff
			elif (rawPacket.haslayer(IP) or rawPacket.haslayer(IPv6)):
				l4 = rawPacket.summary().split("/")[2].strip().split(" ")[0]
				srcIP = rawPacket[0][l3].src
				dstIP = rawPacket[0][l3].dst
				if l3 == 'IP':
					size = rawPacket[0][l3].len
					ttl = rawPacket[0][l3].ttl
				elif l3 == 'IPv6':
					size = rawPacket[0][l3].plen
					ttl = rawPacket[0][l3].hlim
				L7protocol = rawPacket.lastlayer().summary().split(" ")[0].strip()
				if rawPacket.haslayer(ICMP):
					L7protocol = rawPacket.summary().split("/")[2].strip().split(" ")[0]
					payload = rawPacket[ICMP].summary().split("/")[0][5:]
				if rawPacket.haslayer(TCP):
					srcPort = rawPacket[0][l4].sport
					dstPort = rawPacket[0][l4].dport
					L7protocol = rawPacket.summary().split("/")[2].strip().split(" ")[0]
					L4protocol = rawPacket.summary().split("/")[2].strip().split(" ")[0]
				elif rawPacket.haslayer(UDP):
					srcPort = rawPacket[0][l4].sport
					dstPort = rawPacket[0][l4].dport
					L7protocol = rawPacket.summary().split("/")[2].strip().split(" ")[0]
					L4protocol = rawPacket.summary().split("/")[2].strip().split(" ")[0]
			else:
				srcMAC = "<unknown>"
				dstMAC = "<unknown>"
				l4 = "<unknown>"
				srcIP = "<unknown>"
				dstIP = "<unknown>"
				payload = self.cleanPayload(rawPacket[0].show)
				
			packet = {"timestamp": str(datetime.now())[:-2],\
					"srcIP": srcIP,\
					"dstIP": dstIP,\
					"L7protocol": L7protocol,\
					"size": size,\
					"ttl": ttl,\
					"srcMAC": srcMAC,\
					"dstMAC": dstMAC,\
					"L4protocol": L4protocol,\
					"srcPort": srcPort,\
					"dstPort": dstPort,\
					"payload": self.cleanPayload(rawPacket[0].show)\
					}
			return packet
		except:
			# Debug: if packet error, print out the packet to see what failed
			traceback.print_exc(file=sys.stdout)
			print self.cleanPayload(rawPacket[0].show)
			return "Packet Issue, review packet printout for problem"

def parse_arguments():
	usage = "usage: python PacketSniffer.py -c <Number of packets to capture> -f <BPF style filter> -w <pcap file>"
	parser = OptionParser(usage)

	parser.add_option("-c", help="The number of packets to sniff (integer). 0 (default) is indefinite count.", action="store", type="int", dest="pktCount")
	parser.add_option("-f", help="The BPF style filter to sniff with. e.g.-f \"tcp port 80\"", action="store", type="string", dest="filter")
	parser.add_option("-w", help="Name of pcap file", action="store", type="string", dest="pcap")
	parser.add_option("-i", help="Device",action="store", type="string", dest="device")

	if len(sys.argv) == 1:
		parser.print_help()
		sys.exit(0)

	(options, args) = parser.parse_args(sys.argv)

	r = PacketSniffer(options)
	r.main()


if __name__ == "__main__":
	parse_arguments()



