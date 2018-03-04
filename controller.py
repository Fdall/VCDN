from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

class Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    ROUTERMAP = []

'''
    dpid = 1
    router1 = EdgeRouter("b1", dpid, '192.0.0.1', '0xffffff')
    ROUTERMAP[dpid] = router1
'''
    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)
        #Dict with 'dpid':'routerObject'
        self.routers = {}

        #Dict with 'clusterName':'clusterId'
        #MUST be initialized
        self.clusters = {}

        #List of origin server
        #MUST be initialized
        self.handledIps = []

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        self.send_port_desc_stats_request(datapath)
        ip = ROUTERMAP[dpid]
        self.config_edge_router(datapath, ip, mac)


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
        add_arp_reply_flow(datapath, ip, mac)

        #Add table-miss flow
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id
        router = ROUTERMAP[dpid]

        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)
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
                                    ipv4_dst=dst)
            cluster = self.chooseCluster(router, dst)
            actions = router.forwardTo(cluster)
            self.add_flow(datapath, 1, match, actions)
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
        return self.clusters['cluster1']

    def add_arp_reply_flow(self, datapath, arp_tpa, arp_tha):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_ARP,
            arp_op=arp.ARP_REQUEST,
            arp_tpa=arp_tpa)

        actions = [
            parser.NXActionRegMove(
                src_field="eth_src", dst_field="eth_dst", n_bits=48),
            parser.OFPActionSetField(eth_src=arp_tha),
            parser.OFPActionSetField(arp_op=arp.ARP_REPLY),
            parser.NXActionRegMove(
                src_field="arp_sha", dst_field="arp_tha", n_bits=48),
            parser.NXActionRegMove(
                src_field="arp_spa", dst_field="arp_tpa", n_bits=32),
            parser.OFPActionSetField(arp_sha=arp_tha),
            parser.OFPActionSetField(arp_spa=arp_tpa),
            parser.OFPActionOutput(ofproto.OFPP_IN_PORT)]
        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]

        self.add_flow(datapath, 2, match, instructions)


	def send_port_desc_stats_request(self, datapath):
		ofp_parser = datapath.ofproto_parser
		req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
		datapath.send_msg(req)

    #Get the cluster/outputPort mapping on an edgeRouter
	@set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
	def port_desc_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
		ports = {}
		for p in ev.msg.body:
            cluster = re.sub('(.)*gre', 'cluster', p.name)
            portNumber = p.port_no
            ports[cluster] = portNumber
        ROUTERMAP[datapath.id].outMap = ports

class EdgeRouter():
    '''
        name   = router name
        outMap = dict of 'port':'clusterID'
    '''
    def __init__(self, name, dpid, ip, mac)
       self.name = name
       self.dpid = dpid
       self.ip = ip
       self.mac = mac
       self.outMap = {}

    def __hash__(self):
        return hash((self.name, self.dpid))

    def __eq__(self, other):
        return (self.name, self.dpid) == (other.name, other.datapath)

    def forwardTo(self, clusterName):
        actions = [parser.OFPActionOutput(self.outMap[clusterName])]
        return actions
