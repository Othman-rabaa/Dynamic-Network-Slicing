# coding:utf-8

import time
from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import udp
from ryu.lib.packet import tcp
from ryu.lib.packet import icmp
from ryu.lib.packet import ether_types
from ryu.lib import mac, ip
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event
from ryu.ofproto import inet
from collections import defaultdict
from operator import itemgetter
from ryu.base.app_manager import lookup_service_brick
from ryu.lib import hub
import os
import random
import threading
from urllib.parse import urlencode
from ryu.topology import event, switches

REFERENCE_BW = 10000000

DEFAULT_BW = 10000000

MAX_PATHS = 100



class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    DELAY_DETECT_PERIOD = 5

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.datapath_list = {}
        self.arp_table = {}
        self.switches = []
        self.hosts = {}
        self.multipath_group_ids = {}
        self.group_ids = []
        self.links=[]
        self.pathcosts=[]
        self.adjacency = defaultdict(dict)
        self.bandwidths = defaultdict(lambda: defaultdict(lambda: DEFAULT_BW))
        self.prev_bytes = defaultdict(lambda: defaultdict( lambda: 0))
        self.path_table = {} 
        self.paths_table = {} 
        self.path_with_ports_table = {}
        self.usedpaths=[]
        self.link_delay_dict = {}
        self.switch_link_dict = {}
        self.lldp_delay_dict = {}
        self.datapath_dict = {}
        self.echo_delay_dict = {}
        self.hosts_dict = {}
        self.host_arp_dict = {}
        self.switches_module = lookup_service_brick("switches")
        self.detect_thread = hub.spawn(self.delay_detect_loop)
        self.slice_FTPport = 21


    def get_paths(self, src, dst):

        if src == dst:
            return [[src]]
        paths = []
        stack = [(src, [src])]
        while stack:
            (node, path) = stack.pop()
            for next in set(self.switch_link_dict[node].keys()) - set(path):
                if next is dst:
                    paths.append(path + [next])
                else:
                    stack.append((next, path + [next]))
        print ("Available paths from ", src, " to ", dst, " : ", paths)
        return paths

    def get_link_delay(self, s1, s2):

        delay1 = None
        if s1 in self.link_delay_dict.keys():
            delay1 = self.link_delay_dict[s1].get(s2, None)
        delay1 = delay1 if delay1 is not None else float("inf")

        delay2 = None
        if s2 in self.link_delay_dict.keys():
            delay2 = self.link_delay_dict[s2].get(s1, None)
        delay2 = delay2 if delay2 is not None else float("inf")

        return (delay1 + delay2) / 2

    def get_path_delay(self, path):

        delay = 0
        for i in range(len(path) - 1):
            delay += self.get_link_delay(path[i], path[i + 1])

        return (delay*1000)

    def get_link_cost(self, s1, s2):
        
        e1 = self.switch_link_dict[s1][s2]
        e2 = self.switch_link_dict[s2][s1]
        bl = min(self.bandwidths[s1][e1], self.bandwidths[s2][e2])
        ew = REFERENCE_BW/bl
        return ew

    def get_path_cost(self, path):
        bw=0
        cost = []
        for i in range(len(path) - 1):
            cost.append(self.get_link_cost(path[i], path[i+1]))
        if len(cost)>1:
            bw=max(cost)
        return bw

    def get_optimal_paths(self, src, dst):

        paths = self.get_paths(src, dst)
        paths_count = len(paths) if len(
            paths) < MAX_PATHS else MAX_PATHS
        optimalpahts = sorted(paths, key=lambda x: self.get_path_cost(x))[0:(paths_count)]
        return optimalpahts
    def get_optimal_paths_latency(self,src,dst):
        paths = self.get_paths(src, dst)
        paths_count = len(paths) if len(
            paths) < MAX_PATHS else MAX_PATHS
        optimalpahtslatency = sorted(paths, key=lambda x: self.get_path_delay(x))[0:(paths_count)]
        return optimalpahtslatency

    def add_ports_to_paths(self, paths, first_port, last_port):

        paths_p = []
        for path in paths:
            p = {}
            in_port = first_port
            for s1, s2 in zip(path[:-1], path[1:]):
                out_port = self.switch_link_dict[s1][s2]
                p[s1] = (in_port, out_port)
                in_port = self.switch_link_dict[s2][s1]
            p[path[-1]] = (in_port, last_port)
            paths_p.append(p)
        return paths_p


    def install_paths(self, src, first_port, dst, last_port, ip_src, ip_dst,type,pkt):
        if type == 'TCP':
            nw = pkt.get_protocol(ipv4.ipv4)
            l4 = pkt.get_protocol(tcp.tcp) 
        paths_l = self.get_optimal_paths_latency(src, dst)
        for path in paths_l:
            print (path, "cost = ", self.get_path_delay(path))
        paths_with_ports_l = self.add_ports_to_paths(paths_l, first_port, last_port)
        paths = self.get_optimal_paths(src, dst)
        for path in paths:
            print (path, "cost = ", self.get_path_cost(path))
        paths_with_ports = self.add_ports_to_paths(paths, first_port, last_port)
        switches_in_paths = set().union(*paths)
        if len(paths_with_ports)>1:
            if type == 'UDP':
                paths_with_ports0=[paths_with_ports_l[0]]
                print ('selected Ultra-low latency Slice :',paths_with_ports0)
            elif type == 'TCP':
                if (l4.dst_port == 21):
                    paths_with_ports0=[paths_with_ports[0]]
                    print ('selected Ultra-High Bandwidth Slice :',paths_with_ports0)
                if (l4.src_port == 21):
                    paths_with_ports0=[paths_with_ports[0]]
                    print ('selected Ultra-High Bandwidth Slice :',paths_with_ports0)
                else:
                    paths_with_ports0=[paths_with_ports[1]]
                    print ('selected High Bandwidth Slice :',paths_with_ports0)
            elif type == 'ICMP':
                paths_with_ports0=[paths_with_ports_l[0]]
                print ('selected Ultra-low latency Slice :',paths_with_ports0)
            elif type == 'ARP':
                paths_with_ports0=[paths_with_ports_l[0]]
                print ('selected Ultra-low latency Slice :',paths_with_ports0)
        elif len(paths_with_ports)==1:
            paths_with_ports0=[paths_with_ports[0]]
            print ('selected the only Slice:',paths_with_ports0)

        for node in switches_in_paths:
            dp = self.datapath_list[node]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser
            ports = defaultdict(list)
            actions = []
            for path in paths_with_ports0:
                if node in path:
                    in_port = path[node][0]
                    out_port = path[node][1]
                    ports[in_port].append((out_port, 1))
            for in_port in ports:
                if type == 'UDP':
                    nw = pkt.get_protocol(ipv4.ipv4)
                    l4 = pkt.get_protocol(udp.udp)
                    match = ofp_parser.OFPMatch(in_port = in_port,
                                        eth_type=ether_types.ETH_TYPE_IP, 
                                        ipv4_src=ip_src,
                                        ipv4_dst = ip_dst, 
                                        ip_proto=inet.IPPROTO_UDP,
                                        udp_src = l4.src_port, 
                                        udp_dst = l4.dst_port)
                    out_ports = ports[in_port]
                    actions = [ofp_parser.OFPActionOutput(out_ports[0][0])]
                    self.logger.info(f"Installed path in switch: {node} out port: {out_port} in port: {in_port} ")
                    self.add_flow_timeout(dp, 33333, match, actions)
                    self.logger.info("UDP Flow added ! ")
                elif type == 'TCP':
                    nw = pkt.get_protocol(ipv4.ipv4)
                    l4 = pkt.get_protocol(tcp.tcp)
                    match = ofp_parser.OFPMatch(in_port = in_port,
                                        eth_type=ether_types.ETH_TYPE_IP, 
                                        ipv4_src=ip_src, 
                                        ipv4_dst = ip_dst, 
                                        ip_proto=inet.IPPROTO_TCP,
                                        tcp_src = l4.src_port, 
                                        tcp_dst = l4.dst_port)
                    out_ports = ports[in_port]
                    actions = [ofp_parser.OFPActionOutput(out_ports[0][0])]
                    self.logger.info(f"Installed path in switch: {node} out port: {out_port} in port: {in_port} ")
                    self.add_flow_timeout(dp, 44444, match, actions)
                    if (l4.dst_port == 21):
                        self.logger.info("FTP Flow added ! ")
                    if (l4.src_port == 21):
                        self.logger.info("FTP Flow added ! ")
                    else:
                        self.logger.info("TCP Flow added ! ")
                elif type == 'ICMP':
                    nw = pkt.get_protocol(ipv4.ipv4)
                    match = ofp_parser.OFPMatch(in_port=in_port,
                                        eth_type=ether_types.ETH_TYPE_IP, 
                                        ipv4_src=ip_src, 
                                        ipv4_dst = ip_dst, 
                                        ip_proto=inet.IPPROTO_ICMP)
                    out_ports = ports[in_port]
                    actions = [ofp_parser.OFPActionOutput(out_ports[0][0])]
                    self.logger.info(f"Installed path in switch: {node} out port: {out_port} in port: {in_port} ")
                    self.add_flow_timeout(dp, 22222, match, actions)
                    self.logger.info("ICMP Flow added ! ")
                elif type == 'ARP':
                    match_arp = ofp_parser.OFPMatch(in_port = in_port,
                                                eth_type=ether_types.ETH_TYPE_ARP, 
                                                arp_spa=ip_src, 
                                                arp_tpa=ip_dst)
                    out_ports = ports[in_port]
                    actions = [ofp_parser.OFPActionOutput(out_ports[0][0])]
                    self.logger.info(f"Install path in switch: {node} out port: {out_port} in port: {in_port} ")
                    self.add_flow(dp, 1, match_arp, actions)
                    self.logger.info("ARP Flow added ! ")
        return out_ports[0][0]

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match, instructions=inst,
        )
        datapath.send_msg(mod)

    def add_flow_timeout(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser


        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match, instructions=inst, idle_timeout= 5, hard_timeout= 55
        )
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        self.logger.info("[state_change_handler] datapath:%s, event state:%s", datapath.id, ev.state)

        if ev.state == MAIN_DISPATCHER:
            if datapath.id and datapath.id not in self.datapath_dict:
                self.datapath_dict[datapath.id] = datapath


            match_table_miss = ofp_parser.OFPMatch()
            actions = [
                ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)
            ]
            self.add_flow(datapath, 0, match_table_miss, actions)

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapath_dict:
                del self.datapath_dict[datapath.id]
            if datapath.id in self.switch_link_dict:
                del self.switch_link_dict[datapath.id]
            if datapath.id in self.lldp_delay_dict:
                del self.lldp_delay_dict[datapath.id]
            if datapath.id in self.echo_delay_dict:
                del self.echo_delay_dict[datapath.id]
            if datapath.id in self.link_delay_dict:
                del self.link_delay_dict[datapath.id]


    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):

        s1 = ev.link.src
        s2 = ev.link.dst

        self.logger.info("[link_add_handler] %s ——> %s", s1.dpid, s2.dpid)

        self.switch_link_dict.setdefault(s1.dpid, {})
        self.switch_link_dict[s1.dpid][s2.dpid] = s1.port_no
        self.switch_link_dict.setdefault(s2.dpid, {})
        self.switch_link_dict[s2.dpid][s1.dpid] = s2.port_no

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev):

        s1 = ev.link.src
        s2 = ev.link.dst

        self.logger.info("[link_delete_handler] %s ——> %s", s1.dpid, s2.dpid)

        self.switch_link_dict.setdefault(s1.dpid, {})
        if s2.dpid in self.switch_link_dict[s1.dpid]:
            del self.switch_link_dict[s1.dpid][s2.dpid]
        self.switch_link_dict.setdefault(s2.dpid, {})
        if s1.dpid in self.switch_link_dict[s2.dpid]:
            del self.switch_link_dict[s2.dpid][s1.dpid]
    

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        print ("switch_features_handler is called")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        switch = ev.msg.datapath
        for p in ev.msg.body:
            self.bandwidths[switch.id][p.port_no] = p.curr_speed
        self.bandwidths[3][1]= 4000000
        self.bandwidths[3][3]= 5000000
        self.bandwidths[6][2]= 7000000


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        if pkt.get_protocol(ipv6.ipv6):  
            match = parser.OFPMatch(eth_type=eth.ethertype)
            actions = []
            self.add_flow(datapath, 1, match, actions)
            return None

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        if src not in self.hosts:
            self.hosts[src] = (dpid, in_port)

        out_port = ofproto.OFPP_FLOOD

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            nw = pkt.get_protocol(ipv4.ipv4)
            if nw.proto == inet.IPPROTO_UDP:
                l4 = pkt.get_protocol(udp.udp)
            elif nw.proto == inet.IPPROTO_TCP:
                l4 = pkt.get_protocol(tcp.tcp)  

        if eth.ethertype == ether_types.ETH_TYPE_IP and nw.proto == inet.IPPROTO_UDP:
            src_ip = nw.src
            dst_ip = nw.dst
            
            self.arp_table[src_ip] = src
            h1 = self.hosts[src]
            h2 = self.hosts[dst]

            self.logger.info(f" IP Proto UDP from: {nw.src} to: {nw.dst}")

            out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip, 'UDP', pkt)
            self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip, 'UDP', pkt)

        elif eth.ethertype == ether_types.ETH_TYPE_IP and nw.proto == inet.IPPROTO_TCP:
            src_ip = nw.src
            dst_ip = nw.dst
            
            self.arp_table[src_ip] = src
            h1 = self.hosts[src]
            h2 = self.hosts[dst]

            self.logger.info(f" IP Proto TCP from: {nw.src} to: {nw.dst}")

            out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip, 'TCP', pkt)
            self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip, 'TCP', pkt)

        elif eth.ethertype == ether_types.ETH_TYPE_IP and nw.proto == inet.IPPROTO_ICMP:
            src_ip = nw.src
            dst_ip = nw.dst
            
            self.arp_table[src_ip] = src
            h1 = self.hosts[src]
            h2 = self.hosts[dst]


            self.logger.info(f" IP Proto ICMP from: {nw.src} to: {nw.dst}")

            out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip, 'ICMP', pkt)
            self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip, 'ICMP', pkt)
        elif eth.ethertype == ether_types.ETH_TYPE_ARP:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip

            if arp_pkt.opcode == arp.ARP_REPLY:
                self.arp_table[src_ip] = src
                h1 = self.hosts[src]
                h2 = self.hosts[dst]

                self.logger.info(f" ARP Reply from: {src_ip} to: {dst_ip} H1: {h1} H2: {h2}")

                out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip, 'ARP', pkt)
                self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip, 'ARP', pkt) 

            elif arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table:
                    self.arp_table[src_ip] = src
                    dst_mac = self.arp_table[dst_ip]
                    h1 = self.hosts[src]
                    h2 = self.hosts[dst_mac]

                    self.logger.info(f" ARP Reply from: {src_ip} to: {dst_ip} H1: {h1} H2: {h2}")

                    out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip, 'ARP', pkt)
                    self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip, 'ARP', pkt)

        actions = [parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def lldp_packet_in_handler(self, ev):

        recv_timestamp = time.time()

        if self.switches_module is None:
            self.switches_module = lookup_service_brick("switches")
        assert self.switches_module is not None

        if not self.switches_module.link_discovery:
            return

        msg = ev.msg
        try:
            src_dpid, src_port_no = switches.LLDPPacket.lldp_parse(msg.data)
            dst_dpid = msg.datapath.id

            for port in self.switches_module.ports.keys():
                if src_dpid == port.dpid and src_port_no == port.port_no:
                    send_timestamp = self.switches_module.ports[port].timestamp

                    self.lldp_delay_dict.setdefault(src_dpid, {})
                    if send_timestamp:
                        self.lldp_delay_dict[src_dpid][dst_dpid] = recv_timestamp - send_timestamp

        except switches.LLDPPacket.LLDPUnknownFormat:
            return

    def send_echo_request(self):

        for datapath in self.datapath_dict.values():
            ofp_parser = datapath.ofproto_parser
            echo_req = ofp_parser.OFPEchoRequest(datapath, data=(bytearray("%.12f" % time.time(), 'utf-8')))
            datapath.send_msg(echo_req)

    @set_ev_cls(ofp_event.EventOFPEchoReply, MAIN_DISPATCHER)
    def echo_reply_handler(self, ev):

        now_timestamp = time.time()
        try:
            delay = (now_timestamp - eval(ev.msg.data)) / 2
            self.echo_delay_dict[ev.msg.datapath.id] = delay
        except:
            return

    def delay_detect_loop(self):

        while self.is_active:
            self.send_echo_request()
            self.calculate_delay()

            self.show_link_delay()

            hub.sleep(ProjectController.DELAY_DETECT_PERIOD)

         

    def show_link_delay(self):

        if not self.link_delay_dict:
            return

        show_msg = "----------switch link delay----------\n"
        for dp1 in self.link_delay_dict.keys():
            for dp2 in self.link_delay_dict[dp1].keys():
                delay = self.link_delay_dict[dp1][dp2]
                show_msg += "\t%d ————> %d : %.6f ms\n" % (dp1, dp2, delay * 1000)
        show_msg += "-------------------------------------\n"
        #self.logger.info(show_msg)

    def calculate_delay(self):

        for dp1 in self.switch_link_dict.keys():
            self.link_delay_dict.setdefault(dp1, {})

            for dp2 in self.switch_link_dict[dp1].keys():
                if dp1 == dp2:
                    delay = 0
                else:
                    try:
                        lldp_delay1 = self.lldp_delay_dict[dp1][dp2]
                        lldp_delay2 = self.lldp_delay_dict[dp2][dp1]
                        echo_delay1 = self.echo_delay_dict[dp1]
                        echo_delay2 = self.echo_delay_dict[dp2]

                        delay = (lldp_delay1 + lldp_delay2 - echo_delay1 - echo_delay2) / 2
                        delay = max(delay, 0)
                    except:
                      
                        delay = float("inf")

                self.link_delay_dict[dp1][dp2] = delay

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch_dp = ev.switch.dp
        switch_dpid = switch_dp.id
        ofp_parser = switch_dp.ofproto_parser
        
        self.logger.info(f"Switch has been plugged in PID: {switch_dpid}")
            
        if switch_dpid not in self.switches:
            self.datapath_list[switch_dpid] = switch_dp
            self.switches.append(switch_dpid)
            req = ofp_parser.OFPPortDescStatsRequest(switch_dp)
            switch_dp.send_msg(req)


