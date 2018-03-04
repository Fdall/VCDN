import pprint
import process_arp
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from netaddr import IPNetwork, IPAddress
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import arp

class DNat(app_manager.RyuApp):
    'Realise DNAT Service in the entry of the CDN cluster'
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DNat, self).__init__(*args, **kwargs)
        self.siteorigin_sitecache = {'10.0.20.1': '192.168.0.1', "10.0.20.2": '192.168.0.2', '10.0.20.3': '192.168.0.20'}
        self.mac_to_port = {}
        self.ip_to_mac = {}
        self.ip_map = {}  # {  {@src, @dst} , {port_src, port_dst}  }
        self.PORT_TUN = None
        self.PORT_INT = None
        self.PORT_EXT = None
        self.MAC_TUN = None
        self.MAC_INT = None
        self.MAC_EXT = None
        self.ADR_TUN = None
        self.ADR_INT = None
        self.ADR_EXT = None
        self.ADR_GATEWAY = None
        self.src_to_dst = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.config_address_port()

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

    def config_address_port(self, adr_tun='1.1.1.254', adr_int='192.168.1.254', adr_gateway='30.0.0.254', adr_ext='30.0.0.101'):
        self.ADR_TUN = adr_tun
        self.ADR_INT = adr_int
        self.ADR_EXT = adr_ext
        self.ADR_GATEWAY = adr_gateway

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

    def _send_packet_to_port(self, datapath, port, data):
        if data is None:
                # Do NOT sent when data is None
            return
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

    def get_ip_network(self, ip):
        if "/" not in ip:
            return IPAddress(ip)
        return IPNetwork(ip)

    def learn_mac(self, msg, eth, pkt_ipv4):
        dpid = msg.datapath.id
        in_port = msg.match['in_port']
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        self.mac_to_port[dpid][in_port] = (eth.src, pkt_ipv4.src)

    def send_port_desc_stats_request(self, datapath):
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, CONFIG_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        ports = []
        for p in ev.msg.body:
                # ~ print(p)
                # ~ ports.append('port_no=%d hw_addr=%s name=%s config=0x%08x '
                # ~ 'state=0x%08x curr=0x%08x advertised=0x%08x '
                # ~ 'supported=0x%08x peer=0x%08x curr_speed=%d '
                # ~ 'max_speed=%d' %
                # ~ (p.port_no, p.hw_addr,
                # ~ p.name, p.config,
                # ~ p.state, p.curr, p.advertised,
                # ~ p.supported, p.peer, p.curr_speed,
                # ~ p.max_speed))

                # ~ ports.append({
                # ~ 'port_no' : p.port_no,
                # ~ 'hw_addr' : p.hw_addr,
                # ~ 'name' : p.name,
                # ~ 'config' : '0x%08x' % p.config,
                # ~ 'state' : '0x%08x' % p.state,
                # ~ 'curr' : '0x%08x' % p.curr,
                # ~ 'advertised' : '0x%08x' % p.advertised,
                # ~ 'supported' : '0x%08x' % p.supported,
                # ~ 'peer' : '0x%08x' % p.peer,
                # ~ 'curr_speed' : p.curr_speed,
                # ~ 'max_speed' : p.max_speed
                # ~ })

            ports.append(['port_no = %s' % p.port_no,
                          'hw_addr = %s' % p.hw_addr,
                          'name = %s' % p.name,
                          'config = 0x%08x' % p.config])
            # ~ 'state = 0x%08x' % p.state,
            # ~ 'curr = 0x%08x' % p.curr,
            # ~ 'advertised = 0x%08x' % p.advertised,
            # ~ 'supported = 0x%08x' % p.supported,
            # ~ 'peer = 0x%08x' % p.peer,
            # ~ 'curr_speed = %d' % p.curr_speed,
            # ~ 'max_speed = %d' % p.max_speed

            if p.name == 'clu1r1-eth1':
                self.PORT_TUN = p.port_no
                self.MAC_TUN = p.hw_addr
            elif p.name == 'clu1r1-eth0':
                self.PORT_INT = p.port_no
                self.MAC_INT = p.hw_addr
            elif p.name == 'clu1r1-eth2':
                self.PORT_EXT = p.port_no
                self.MAC_EXT = p.hw_addr

            # ~ ports.append(p)
            # ~ self.logger.debug('OFPPortDescStatsReply received: %s', ports)
            print('OFPPortDescStatsReply dpid %d received:' % ev.msg.datapath.id)
            pprint.pprint(ports)

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

    def _arp_reply_handler(self, pkt_arp):
        """
        Handle ARP reply packets.
        When controller get an ARP reply packet, it will write into ARP table.
        """
        if pkt_arp.opcode != arp.ARP_REPLY:
            print '[WARRING] Wrong ARP opcode!'
            return None

        if (pkt_arp.dst_ip == self.ADR_TUN) or (pkt_arp.dst_ip == self.ADR_INT) or (pkt_arp.dst_ip == self.ADR_EXT):
            self.ip_to_mac[pkt_arp.src_ip] = pkt_arp.src_mac

        # ---------------------------------END ARP------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        print "NAT: Packet in"
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("NAT: packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        # Decide the exit port and mac address
        if in_port == self.PORT_TUN:
            out_port = self.PORT_INT
        elif in_port == self.PORT_INT:
            out_port = self.PORT_EXT
        else:
            out_port = self.PORT_INT

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        self.learn_mac(msg, eth, pkt_ipv4)

        # decide if tcp or udp this packet
        _tcp = pkt.get_protocol(tcp.tcp)
        _udp = pkt.get_protocol(udp.udp)
        _arp = pkt.get_protocol(arp.arp)

        tcp_udp = _tcp if _tcp else _udp
        ports = {'port_dst': _tcp.dst_port if _tcp else _udp.dst_port,
                 'port_src': _tcp.src_port if _tcp else _udp.src_port}
        self.ip_map.setdefault(pkt_ipv4.src, ports)
        self.src_to_dst = {self.ip_map: pkt_ipv4.dst}
        # -----------------------IF Packet is ARP-----------------------------------
        if in_port == self.PORT_TUN:
            if _arp:
                if _arp.opcode == arp.ARP_REQUEST:
                    arp_reply_pkt = self._arp_request_handler(_arp)
                    self._send_packet_to_port(datapath, in_port, arp_reply_pkt)
                elif _arp.opcode == arp.ARP_REPLY:
                    self._arp_reply_handler(_arp)
                # process of DNAT to change destination IP address
            if pkt_ipv4.dst in self.siteorigin_sitecache:
                cache_dst = self.siteorigin_sitecache[pkt_ipv4.dst]

            # if packet for destination surrogate, we send alls to one fixe surrogate : 193.168.0.1
            # elif ('192.168.1.' in pkt_ipv4.dst) or (pkt_ipv4.dst == '30.0.0.30'):
            # -------------------------find content not cached in cluster or other packet for surrogate----
            else:
                cache_dst = '192.168.0.1'

            # ---------------------------------------------------------------------------------------------
            # Sending ARP request to for surrogate
            arp_req_pkt_surrogate = process_arp.broadcast_arp_request(src_mac=self.MAC_INT,
                                                                      src_ip=self.ADR_INT,
                                                                      target_ip=cache_dst)
            self._send_packet_to_port(datapath, out_port, arp_req_pkt_surrogate)
            # Sending ARP request to gateway
            arp_req_pkt_gateway = process_arp.broadcast_arp_request(src_mac=self.MAC_INT,
                                                                    src_ip=self.ADR_INT,
                                                                    target_ip=self.ADR_GATEWAY)
            self._send_packet_to_port(datapath, self.PORT_EXT, arp_req_pkt_gateway)
            # Push new flow to the table
            if cache_dst in self.ip_to_mac:
                match_go = parser.OFPMatch(in_port=in_port,
                                           eth_type=ether.ETH_TYPE_IP,
                                           ipv4_dst=pkt_ipv4.dst,
                                           ipv4_src=pkt_ipv4.src,
                                           tcp_dst=tcp_udp.dst_port,
                                           tcp_src=tcp_udp.src_port)
                actions_go = [parser.OFPActionSetField(ipv4_dst=cache_dst),
                              parser.OFPActionOutput(out_port),
                              parser.OFPActionSetField(eth_src=self.MAC_INT),
                              parser.OFPActionSetField(eth_dst=self.ip_to_mac[cache_dst])]

                # Push new flow to the table
                self.add_flow(datapath, 10, match_go, actions_go)

                match_back = parser.OFPMatch(in_port=out_port,
                                             eth_type=ether.ETH_TYPE_IP,
                                             ipv4_dst=pkt_ipv4.src,
                                             ipv4_src=cache_dst,
                                             tcp_src=tcp_udp.dst_port,
                                             tcp_dst=tcp_udp.src_port)

                actions_back = [parser.OFPActionSetField(ipv4_src=pkt_ipv4.dst),
                                parser.OFPActionOutput(self.PORT_EXT),
                                parser.OFPActionSetField(eth_src=self.MAC_EXT),
                                parser.OFPActionSetField(eth_dst=self.ip_to_mac[self.ADR_GATEWAY])]

                self.add_flow(datapath, 10, match_back, actions_back)
                # Return the packet_out to the switch
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions_go, data=data)
                datapath.send_msg(out)
            elif self.ADR_GATEWAY in self.ip_to_mac:
                print ('MAC Address of %s not found successful in cluster, '
                       'starting reforwarding to gateway' % cache_dst)
                match_alt = parser.OFPMatch(in_port=in_port,
                                            eth_type=ether.ETH_TYPE_IP,
                                            ipv4_dst=pkt_ipv4.dst,
                                            ipv4_src=pkt_ipv4.src,
                                            tcp_dst=tcp_udp.dst_port,
                                            tcp_src=tcp_udp.src_port)
                actions_alt = [parser.OFPActionOutput(self.PORT_EXT),
                               parser.OFPActionSetField(eth_src=self.MAC_EXT),
                               parser.OFPActionSetField(eth_dst=self.ip_to_mac[self.ADR_GATEWAY])]

                # Push new flow to the table
                self.add_flow(datapath, 10, match_alt, actions_alt)
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions_alt, data=data)
                datapath.send_msg(out)
            else:
                    # Disconnected switch, drop this packet
                print ('MAC Address of %s not found successful in the complete network..........' % cache_dst)
                pass
        elif in_port == self.PORT_INT:
            if _arp:
                if _arp.opcode == arp.ARP_REQUEST:
                    arp_reply_pkt = self._arp_request_handler(_arp)
                    self._send_packet_to_port(datapath, in_port, arp_reply_pkt)
                elif _arp.opcode == arp.ARP_REPLY:
                    self._arp_reply_handler(_arp)
            else:
                    # Sending ARP request to gateway
                arp_req_pkt_gateway = process_arp.broadcast_arp_request(src_mac=self.MAC_EXT,
                                                                        src_ip=self.ADR_EXT,
                                                                        target_ip=self.ADR_GATEWAY)
                self._send_packet_to_port(datapath, out_port, arp_req_pkt_gateway)
                if self.ADR_GATEWAY in self.ip_to_mac:
                    match_content = parser.OFPMatch(in_port=in_port,
                                                    eth_type=ether.ETH_TYPE_IP,
                                                    ipv4_dst=pkt_ipv4.dst,
                                                    ipv4_src=pkt_ipv4.src,
                    #always 192.168.0.1 surrogate 1 here for reserche the content absent
                                                    tcp_src=tcp_udp.src_port,
                                                    tcp_dst=tcp_udp.dst_port)

                    actions_content = [parser.OFPActionOutput(out_port),
                                       parser.OFPActionSetField(eth_src=self.MAC_EXT),
                                       parser.OFPActionSetField(eth_dst=self.ip_to_mac[self.ADR_GATEWAY])]

                    self.add_flow(datapath, 10, match_content, actions_content)
                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                              in_port=in_port, actions=actions_content, data=data)
                    datapath.send_msg(out)
        # elif in_port == self.PORT_EXT:
        #     if _arp:
        #         if _arp.opcode == arp.ARP_REQUEST:
        #             arp_reply_pkt = self._arp_request_handler(_arp)
        #             self._send_packet_to_port(datapath, in_port, arp_reply_pkt)
        #         elif _arp.opcode == arp.ARP_REPLY:
        #             self._arp_reply_handler(_arp)
        #     if pkt_ipv4.dst in self.siteorigin_sitecache.values():
        #         cache_dst = self.siteorigin_sitecache[pkt_ipv4.dst]