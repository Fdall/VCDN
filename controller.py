from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet


class Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
	self.routing_flow(datapath)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def routing_flow(self, datapath):
        S1_SUBNET = '192.168.0.1'
        S2_SUBNET = '192.168.0.2'
        S3_SUBNET = '192.168.0.3'

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #S1 subnet dst
        actions = [parser.OFPActionOutput(1)]
        match = parser.OFPMatch(
        	eth_type=0x800,
        	ipv4_dst=S1_SUBNET)
        self.add_flow(datapath, 1, match, actions)

        #S2 subnet dst
        actions = [parser.OFPActionOutput(2)]
        match = parser.OFPMatch(
        	eth_type=0x800,
        	ipv4_dst=S2_SUBNET)
        self.add_flow(datapath, 1, match, actions)

        #S3 subnet dst
        actions = [parser.OFPActionOutput(3)]
        match = parser.OFPMatch(
        	eth_type=0x800,
        	ipv4_dst=S3_SUBNET)
        self.add_flow(datapath, 1, match, actions)
