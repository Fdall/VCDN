from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from netaddr import IPNetwork, IPAddress
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp

import process_arp

import re
import pprint



'''
	IDEA:
		At booting time,
			- Get clusters infos from each edge
			- Make a map of it in each edge object on the controller
			- Add an ARP REPLY flow on each edge
			- Add a table miss flow

		Packet-In,
			- Get source edge from dpid
			- check if IPV4 dst is a source server on the cdn
				YES, choose a cluster to forward the request
					 get the associated port
					 make the flow
				NO, drop

'''

class Controller(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(Controller, self).__init__(*args, **kwargs)
		
		
		self.bridge_route = {
			'b1' : 'cluster1',
			'b2' : 'cluster2',
			'b3' : 'cluster1'
		}
		
		
		#List of the clusters' name
		#MUST be initialized
		self.clusters = ['cluster1', 'cluster2']
		self.edgeMap = {}
		#List of origin server
		#MUST be initialized
		self.handledIps = ['100.0.0.1', '100.0.0.5', '30.0.0.254']
		
		self.arp_reply_handler = {}

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		dpid = datapath.id
		self.send_port_desc_stats_request(datapath)
		
			
	
	
	
	def send_port_desc_stats_request(self, datapath):
		ofp_parser = datapath.ofproto_parser
		req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
		datapath.send_msg(req)

	#Get the cluster/outputPort mapping on an edgeRouter
	@set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
	def port_desc_stats_reply_handler(self, ev):
		dpid = ev.msg.datapath.id

		ports = []

		datapath = ev.msg.datapath
		clusters = {}
		mac = {}

		for p in ev.msg.body:
			ports.append(['port_no = %s' % p.port_no,
						  'hw_addr = %s' % p.hw_addr,
						  'name = %s' % p.name,
						  'config = 0x%08x' % p.config])

			portNumber = p.port_no

			mac[portNumber] = p.hw_addr

			#TODO faire une demande de la vraie adresse
			
			if '-' in p.name:
				if 'gre' in p.name:
					# ------------------------------- Get MAC of each gre port -----------------------------------------------------
					# Sending ARP request for gre GW
					#~ arp_req_pkt = process_arp.broadcast_arp_request(src_mac=p.hw_addr,
																	#~ src_ip='1.1.1.1',
																	#~ target_ip='1.1.1.254')
					#~ self._send_packet_to_port(datapath, portNumber, arp_req_pkt)


					clusterName = re.sub('(.)*gre', 'cluster', p.name)
					cluster = Cluster(clusterName, portNumber, None)
					clusters[clusterName] = cluster
				else:
					self.localPort = p.port_no
			

		router = EdgeRouter('b%d' % dpid, dpid, '10.%d.0.254' % dpid, mac, clusters)
		self.edgeMap[dpid] = router
		
		print('OFPPortDescStatsReply dpid %d received:' % dpid)
		pprint.pprint(ports)
		
		pprint.pprint(self.edgeMap)
		ip = self.edgeMap[dpid].ip
		mac = self.edgeMap[dpid].mac
		self.config_edge_router(ev.msg.datapath, ip, mac)


	
	def _send_packet_to_port(self, datapath, port, data):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		actions = [parser.OFPActionOutput(port=port)]
		# self.logger.info("packet-out %s" % (data,))
		out = parser.OFPPacketOut(datapath=datapath,
								  buffer_id=ofproto.OFP_NO_BUFFER,
								  in_port=ofproto.OFPP_CONTROLLER,
								  actions=actions,
								  data=data)
		datapath.send_msg(out)	



	# ----------------------------ARP Handler-----------------------------------------------

	def _arp_request_handler(self, pkt_arp):
		"""Handle ARP request packets.
		When controller get an ARP request packet,
		it will reply someone who want to ask NAT's MAC address.
		"""
		data = None

		if pkt_arp.opcode != arp.ARP_REQUEST:
			print '[WARRING] Wrong ARP opcode!'
			return None


		
		if pkt_arp.dst_ip == str(self.ADR_TUN):
				# Who has 1.1.1.254 ?
				# Tell 1.1.1.1(other end of tunnel gre),
				# router cluster's fake MAC address (eth1)
			data = process_arp.arp_reply(src_mac=self.MAC_TUN,
										 src_ip=str(self.ADR_TUN),
										 target_mac=pkt_arp.src_mac,
										 target_ip=pkt_arp.src_ip)

		elif pkt_arp.dst_ip == str(self.ADR_INT):
				# Who has 192.168.0.254 ?
				# Tell 192.168.1.xxx(Address of surrogate server)
			data = process_arp.arp_reply(src_mac=self.MAC_INT,
										 src_ip=self.ADR_INT,
										 target_mac=pkt_arp.src_mac,
										 target_ip=pkt_arp.src_ip)

		elif pkt_arp.dst_ip == str(self.ADR_EXT):
				# Who has 30.0.0.101 ?
				# Tell 30.0.0.254(Address gateway)
			data = process_arp.arp_reply(src_mac=self.MAC_EXT,
										 src_ip=self.ADR_EXT,
										 target_mac=pkt_arp.src_mac,
										 target_ip=pkt_arp.src_ip)
		
		return data

	def _arp_reply_handler(self, pkt_arp, in_port, router):
		"""
		Handle ARP reply packets.
		When controller get an ARP reply packet, it will write into ARP table.
		"""
		cluster = None
		for iCluster in router.outMap.values():
			if iCluster.port == in_port:
				cluster = iCluster
				pass
				
		print pkt_arp.dst_ip
		if pkt_arp.dst_ip == '1.1.1.1':
			cluster.mac = pkt_arp.src_mac
		'''
		if pkt_arp.opcode != arp.ARP_REPLY:
			print '[WARRING] Wrong ARP opcode!'
			return None

		if (pkt_arp.dst_ip == self.ADR_TUN) or (pkt_arp.dst_ip == self.ADR_INT) or (pkt_arp.dst_ip == self.ADR_EXT):
			self.ip_to_mac[pkt_arp.src_ip] = pkt_arp.src_mac
			
			clusterName = re.sub('(.)*gre', 'cluster', p.name)
			macBroadcast = 'ff:ff:ff:ff:ff:ff'
			cluster = Cluster(clusterName, portNumber, macBroadcast)
			clusters[clusterName] = cluster
		'''
		self._exe_arp_reply_handler(pkt_arp.src_ip)

	

	def _add_arp_reply_handler(self, ip, fc, *args, **kwargs):
		handler = {
			'func' : fc,
			'args' : args,
			'kwargs' : kwargs
		}
		
		if ip not in self.arp_reply_handler:
			self.arp_reply_handler[ip] = []
		
		self.arp_reply_handler[ip].append(handler)
		
		
	def _exe_arp_reply_handler(self, ip):
		if ip in self.arp_reply_handler:
			for handler in self.arp_reply_handler[ip]:
				handler.func(*(handler.args), **(handler.kwargs))
				self.arp_reply_handler[ip].remove(handler)

	# ---------------------------------END ARP------------------------------------------------------


	def add_flow(self, datapath, priority, match, actions):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# construct flow_mod message and send it.
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
											 actions)]
		mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
								match=match, instructions=inst)
		datapath.send_msg(mod)

	def config_edge_router(self, datapath, ip, mac):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		#set ARP flows
		#Answer ARP REQUEST
		self.add_arp_reply_flow(datapath, [ip, '1.1.1.1'], mac)

		#Add table-miss flow
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
										  ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		in_port = msg.match['in_port']
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# analyse the received packets using the packet library.
		pkt = packet.Packet(msg.data)

		# get Datapath ID to identify OpenFlow switches.
		dpid = datapath.id
		router = self.edgeMap[dpid]
		
		
		# -----------------------IF Packet is ARP-----------------------------------
		
		_arp = pkt.get_protocol(arp.arp)
		
		if _arp:
			print "ARP"
			if _arp.opcode == arp.ARP_REQUEST:
				print 'ARP request'
				#~ arp_reply_pkt = self._arp_request_handler(_arp)
				#~ self._send_packet_to_port(datapath, in_port, arp_reply_pkt)
			elif _arp.opcode == arp.ARP_REPLY:
				print 'ARP reply'
				self._arp_reply_handler(_arp, in_port, router)
			# process of DNAT to change destination IP address
		

		# -----------------------IF Packet is IPv4-----------------------------------
		pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
		if not pkt_ipv4:
			return
		else:
			ip_dst = pkt_ipv4.dst
			print(pkt_ipv4.src + " => " + ip_dst)

		# Add a flow rule to avoid next packet
		if ip_dst in self.handledIps:
			#Add a rule to forward to given cluster
			match = parser.OFPMatch(in_port=in_port,
									eth_type=0x800,
									ipv4_dst=ip_dst)
			#Select the cluster to forward the requests
			clusterName = self.chooseCluster(router, ip_dst)
			#Use the clusters per edge Map find the infos
			
			cluster = router.outMap[clusterName]
			if cluster.mac:
				actions = router.forwardTo(clusterName, datapath)
				self.add_flow(datapath, 1, match, actions)
			else:
				port = cluster.port
				src_mac = router.mac[port]
				arp_req_pkt = process_arp.broadcast_arp_request(src_mac=src_mac,
																src_ip='1.1.1.1',
																target_ip='1.1.1.254')
				self._send_packet_to_port(datapath, port, arp_req_pkt)
				
				self._add_arp_reply_handler(self._packet_in_handler, ev)
				return

		else:
			#Add a drop table
			print("Packet dropped")
			return

		
		# construct packet_out message and send it.
		out = parser.OFPPacketOut(datapath=datapath,
								  buffer_id=ofproto.OFP_NO_BUFFER,
								  in_port=in_port, actions=actions,
								  data=msg.data)
		datapath.send_msg(out)

	def chooseCluster(self, router, dst):
		#TODO change this . . .
		## Must return cluster Name
		#~ return self.clusters[0]
		if router.name in self.bridge_route:
			return self.bridge_route[router.name]
		else:
			return self.clusters[0]

	def add_arp_reply_flow(self, datapath, arp_tpa, arp_tha):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		priority = 1
		for iIP in arp_tpa:
			for iMac in arp_tha:
				priority = priority+1
				
				match = parser.OFPMatch(
					eth_type=ether_types.ETH_TYPE_ARP,
					arp_op=arp.ARP_REQUEST,
					arp_tpa=iIP)

				actions = [
					parser.NXActionRegMove(
						src_field="eth_src", dst_field="eth_dst", n_bits=48),
					parser.OFPActionSetField(eth_src=iMac),
					parser.OFPActionSetField(arp_op=arp.ARP_REPLY),
					parser.NXActionRegMove(
						src_field="arp_sha", dst_field="arp_tha", n_bits=48),
					parser.NXActionRegMove(
						src_field="arp_spa", dst_field="arp_tpa", n_bits=32),
					parser.OFPActionSetField(arp_sha=iMac),
					parser.OFPActionSetField(arp_spa=iIP),
					parser.OFPActionOutput(ofproto.OFPP_IN_PORT)]
				'''
				instructions = [
					parser.OFPInstructionActions(
						ofproto.OFPIT_APPLY_ACTIONS, actions)]
				'''

				self.add_flow(datapath, priority, match, actions)




class EdgeRouter():
	#    name   = router name
	#    outMap = dict of 'port':'clusterObject'
	def __init__(self, name, dpid, ip, mac, clusters):
	   self.name = name
	   self.dpid = dpid
	   self.ip = ip
	   self.mac = mac
	   self.outMap = clusters

	def __hash__(self):
		return hash((self.name, self.dpid))

	def __eq__(self, other):
		return (self.name, self.dpid) == (other.name, other.datapath)

	def forwardTo(self, clusterName, datapath):
		parser = datapath.ofproto_parser
		actions = [parser.OFPActionSetField(eth_dst=self.outMap[clusterName].mac)]
		actions += [parser.OFPActionOutput(self.outMap[clusterName].port)]
		return actions


class Cluster():
	#    name = cluster name
	#    port = ovs port number to reach the cluster from the edge router
	#    mac = cluster's mac adress
   def __init__(self, name, port, mac):
	   self.name = name
	   self.mac = mac
	   self.port = port

   def __hash__(self):
	   return hash(self.name)

   def __eq__(self, other):
	   return (self.name) == (other.name)
