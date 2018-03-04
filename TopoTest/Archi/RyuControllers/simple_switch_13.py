# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4

import pprint

class SimpleSwitch13(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(SimpleSwitch13, self).__init__(*args, **kwargs)
		self.mac_to_port = {}

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		
		
		# install table-miss flow entry
		#
		# We specify NO BUFFER to max_len of the output action due to
		# OVS bug. At this moment, if we specify a lesser number, e.g.,
		# 128, OVS will send Packet-In with invalid buffer_id and
		# truncated packet data. In that case, we cannot output packets
		# correctly.  The bug has been fixed in OVS v2.1.0.
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
										  ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)

		# Send request to find ports		
		self.send_port_desc_stats_request(datapath)



	def send_port_desc_stats_request(self, datapath):
		ofp_parser = datapath.ofproto_parser

		req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
		datapath.send_msg(req)


	@set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
	def port_desc_stats_reply_handler(self, ev):
		ports = []
		for p in ev.msg.body:
			#~ print(p)
			#~ ports.append('port_no=%d hw_addr=%s name=%s config=0x%08x '
						 #~ 'state=0x%08x curr=0x%08x advertised=0x%08x '
						 #~ 'supported=0x%08x peer=0x%08x curr_speed=%d '
						 #~ 'max_speed=%d' %
						 #~ (p.port_no, p.hw_addr,
						  #~ p.name, p.config,
						  #~ p.state, p.curr, p.advertised,
						  #~ p.supported, p.peer, p.curr_speed,
						  #~ p.max_speed))
			
			#~ ports.append({
				#~ 'port_no' : p.port_no,
				#~ 'hw_addr' : p.hw_addr,
				#~ 'name' : p.name,
				#~ 'config' : '0x%08x' % p.config,
				#~ 'state' : '0x%08x' % p.state,
				#~ 'curr' : '0x%08x' % p.curr,
				#~ 'advertised' : '0x%08x' % p.advertised,
				#~ 'supported' : '0x%08x' % p.supported,
				#~ 'peer' : '0x%08x' % p.peer,
				#~ 'curr_speed' : p.curr_speed,
				#~ 'max_speed' : p.max_speed
			#~ })
			
			ports.append([
				'port_no = %s' % p.port_no,
				'hw_addr = %s' % p.hw_addr,
				'name = %s' % p.name,
				'config = 0x%08x' % p.config,
				#~ 'state = 0x%08x' % p.state,
				#~ 'curr = 0x%08x' % p.curr,
				#~ 'advertised = 0x%08x' % p.advertised,
				#~ 'supported = 0x%08x' % p.supported,
				#~ 'peer = 0x%08x' % p.peer,
				#~ 'curr_speed = %d' % p.curr_speed,
				#~ 'max_speed = %d' % p.max_speed
			])
				  
			#~ ports.append(p)
		#~ self.logger.debug('OFPPortDescStatsReply received: %s', ports)
		print('OFPPortDescStatsReply dpid %d received:' % ev.msg.datapath.id)
		pprint.pprint(ports)
		




	def add_flow(self, datapath, priority, match, actions, buffer_id=None):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
											 actions)]
		if buffer_id:
			mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
									priority=priority, match=match,
									instructions=inst)
		else:
			mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
									match=match, instructions=inst)
		datapath.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		# If you hit this you might want to increase
		# the "miss_send_length" of your switch
		if ev.msg.msg_len < ev.msg.total_len:
			self.logger.debug("packet truncated: only %s of %s bytes",
							  ev.msg.msg_len, ev.msg.total_len)
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']

		pkt = packet.Packet(msg.data)
		
		self.logger.info("packet-in %s" % (pkt,))
		
		# Get ethernet
		eth = pkt.get_protocols(ethernet.ethernet)[0]

		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
			# ignore lldp packet
			return
		dst = eth.dst
		src = eth.src

		# Get IP
		ip = pkt.get_protocols(ipv4.ipv4)

		dpid = datapath.id
		self.mac_to_port.setdefault(dpid, {})

		self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
		
		self.logger.info(len(ip))

		# learn a mac address to avoid FLOOD next time.
		self.mac_to_port[dpid][src] = in_port

		if dst in self.mac_to_port[dpid]:
			out_port = self.mac_to_port[dpid][dst]
		else:
			#~ out_port = ofproto.OFPP_FLOOD
			out_port = 3

		actions = [parser.OFPActionOutput(out_port)]

		# install a flow to avoid packet_in next time
		if out_port != ofproto.OFPP_FLOOD:
			match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
			# verify if we have a valid buffer_id, if yes avoid to send both
			# flow_mod & packet_out
			if msg.buffer_id != ofproto.OFP_NO_BUFFER:
				self.add_flow(datapath, 1, match, actions, msg.buffer_id)
				return
			else:
				self.add_flow(datapath, 1, match, actions)
		data = None
		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
			data = msg.data

		out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
								  in_port=in_port, actions=actions, data=data)
		datapath.send_msg(out)
