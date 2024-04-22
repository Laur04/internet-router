import threading, time
from scapy.all import sendp, sniff
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, ARP

from structures import CPUMetadata, Graph, Interface, Neighbor, pwospfHeader, pwospfHello, pwospfLink, pwospfLSU


ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002
BCAST_GRP    = 0x1


class Controller(threading.Thread):
    # Basic control functions
    def __init__(self, sw, mac, switch_ip, area_id=1, hello_int=30, lsu_int=30, interface_ports_ips=[]):
        super(Controller, self).__init__()
        # General configuration
        self.sw = sw  # store switch object
        self.controller_iface = sw.intfs[1].name  # determine interface between switch and this controller
        
        # Configure MAC for all ports
        self.mac = mac
        for intf in sw.intfList():
            sw.setMAC(mac, intf)

        # Configure switching
        for intf in sw.intfList():
            sw.setIP(switch_ip, intf)  # initialize all port IPs to the basic switch IP
        sw.addMulticastGroup(mgid=BCAST_GRP, ports=range(2, len(sw.intfs) + 1))  # add ARP broadcast

        # Controller tables
        self.ip_list = [switch_ip]  # tracks local table send_to_controller action
        self.port_for_local_ip = {}  # tracks local table foward_local action
        self.mac_for_ip = {}  # tracks arp table
        self.routing = {}  # tracks routing table

        # Other internal data structures
        self.waitingForARP = {}  # tracks packets waiting for an ARP response
        self.graph = Graph()  # initializes OSPF graph
        self.interfaces = {}  # tracks PWOSPF interfaces associated with this router

        # Configure PWOSPF
        self.router_id = switch_ip
        self.area_id = area_id
        self.lsu_int = lsu_int

        # Initialize interfaces
        for port, ip, subnet, mask in interface_ports_ips:
            newInt = Interface(ip, subnet, mask, port, hello_int=hello_int)  # create new structure
            self.interfaces[port] = newInt  # add interface to list
            sw.setIP(ip, sw.intfs[port])  # set the interface IP
            self.ip_list.append(ip)  # add the IP to the send_to_controller list
            vertex, _ = self.graph.add_vertex_data((subnet, mask))  # add the subnet of this interface to the graph
            self.graph.connect_range(self.router_id, vertex)  # connect the interface to all others

        # Add switch "interface" to graph
        self.vertex_ind, _ = self.graph.add_switch_data(None, self.router_id)
        self.graph.connect_range(self.router_id, self.vertex_ind)

    def start(self, *args, **kwargs):
        super(Controller, self).start(*args, **kwargs)
        time.sleep(0.3)

    def join(self, *args, **kwargs):
        super(Controller, self).join(*args, **kwargs)

    def run(self):
        # Set up source mac table
        for intf in self.sw.intfList():
            self.sw.insertTableEntry(
                table_name='MyEgress.source_mac',
                match_fields={'standard_metadata.egress_spec': [self.sw.ports[intf]]},
                action_name='MyEgress.set_src_mac',
                action_params={'srcMac': self.mac}
            )
        
        # Add switch IP and OSPF interfaces to local table
        for ip in self.ip_list:
            self.sw.insertTableEntry(
                table_name='MyIngress.local',
                match_fields={'hdr.ipv4.dstAddr': ip},
                action_name='MyIngress.send_to_controller',
            )

        # Start hello timers on each interface
        for intf in self.interfaces.values():
            threading.Timer(intf.hello_int, self.send_pwospf_hello, args=(intf,)).start()

        # Start lsu timer
        threading.Timer(self.lsu_int, self.send_pwospf_lsu).start()

        # Start packet sniffer
        sniff(iface=self.controller_iface, prn=self.handlePkt)

    def send_pwospf_hello(self, intf):
        cpuMeta = CPUMetadata(
            origEtherType = 0x0800,
            origSrcPort = intf.port
        )
        ip = IP(
            proto=89,
            src=intf.ip_address,
            dst="224.0.0.5"
        )
        pwospf = pwospfHeader(
            type=0x01,
            packetLength=32,
            routerID=self.router_id,
            areaID=self.area_id,
            checksum=0
        )
        hello = pwospfHello(
            networkMask = intf.mask,
            helloInt = intf.hello_int,
        )

        self.send(Ether() / cpuMeta / ip / pwospf / hello)

        time.sleep(intf.hello_int)
        self.send_pwospf_hello(intf)

    def create_lsu(self):
        count = 0
        update = []
        for ip in self.port_for_local_ip.values():
            update.append(pwospfLink(subnet=ip, mask=32, routerID="0.0.0.0"))
            count += 1
        for intf in self.interfaces.values():
            for neighbor in intf.neighbors.values():
                update.append(pwospfLink(subnet=intf.subnet, mask=intf.mask, routerID=neighbor.rid))
                count += 1
        return count, update

    def send_pwospf_lsu(self):
        count, updates = self.create_lsu()
        for port in self.interfaces.keys():
            for neighbor in self.interfaces[port].neighbors.values():
                cpuMeta = CPUMetadata(
                    origEtherType = 0x0800,
                    origSrcPort = port
                )
                ip = IP(
                    proto=89,
                    src=self.interfaces[port].ip_address,
                    dst=neighbor.ip_address
                )
                pwospf = pwospfHeader(
                    type=4,
                    packetLength=32 + (12 * count),
                    routerID=self.router_id,
                    areaID=self.area_id,
                    checksum=0
                )
                lsu = pwospfLSU(
                    sequence = neighbor.send_sequence,
                    ttl = 254,
                    numAdvertisements = count
                )
                for update in updates:
                    lsu /= update
                neighbor.send_sequence += 1
                self.send(Ether() / cpuMeta / ip / pwospf / lsu)

        time.sleep(self.lsu_int)
        self.send_pwospf_lsu()

    def timeout_arp(self):
        pass

    def timeout_hello(self):
        pass

    def timeout_lsu(self):
        pass

    # Main packet handling logic function
    def handlePkt(self, pkt):
        # print(pkt.show(dump=True))
        if CPUMetadata not in pkt:
            return

        # Process IPv4 packets
        if IP in pkt:
            if pkt[CPUMetadata].awaitingARP == 1:  # If the packet was sent to the CPU because it needs an entry added to the ARP table
                # If there is already a packet in the queue waiting for the same request
                if pkt[IP].dst in self.waitingForARP:                    
                    # Add this packet to the waiting queue
                    self.waitingForARP[pkt[IP].dst].append(pkt)
                else:
                    # Add an entry to the dictionary of waiting packets
                    self.waitingForARP[pkt[IP].dst] = [pkt]
                    # Send an ARP request for the given IP.dst
                    self.send_arp_request(pkt)
            elif pwospfHeader in pkt:
                # Do basic PWOSPF verification
                if pkt[pwospfHeader].version == 0x2 and pkt[pwospfHeader].areaID == self.area_id and pkt[pwospfHeader].autype == 0 and pkt[pwospfHeader].routerID != self.router_id:
                    if pwospfHello in pkt:
                        if pkt[IP].dst == "224.0.0.5":
                            receivingInt = self.interfaces[pkt[CPUMetadata].origSrcPort]
                            if pkt[pwospfHello].networkMask == receivingInt.mask and pkt[pwospfHello].helloInt == receivingInt.hello_int:
                                if pkt[IP].src in receivingInt.neighbors.keys():
                                    receivingInt.neighbors[pkt[IP].src].last_seen = time.perf_counter()
                                else:
                                    receivingInt.neighbors.update({pkt[IP].src: Neighbor(pkt[IP].src, pkt[pwospfHeader].routerID, time=time.perf_counter())})                            
                    elif pwospfLSU in pkt:
                        receivingInt = self.interfaces[pkt[CPUMetadata].origSrcPort]
                        rid = pkt[pwospfHeader].routerID

                        # If the packet isn't from a known neighbor, drop it
                        if pkt[IP].src not in receivingInt.neighbors.keys():
                            return
                        # If the packet has an old sequence number, drop it
                            #TODO
                                                
                        # Update the database
                        updated = False
                        verticies = set()
                        for lsu in pkt[pwospfLSU].advs:
                            if lsu.routerID != "0.0.0.0":
                                vertex, updated = self.graph.add_vertex_data((lsu.subnet, lsu.mask))
                                verticies.add(vertex)
                            else:
                                vertex, updated = self.graph.add_switch_data(lsu.subnet, rid)
                                verticies.add(vertex)
                        t = time.perf_counter()
                        for v1 in verticies:
                            for v2 in verticies:
                                updated = self.graph.add_edge(v1, v2, rid, t) or updated

                        if updated:
                            # Flood the packet
                            for port in self.interfaces:
                                    intf = self.interfaces[port]
                                    for n_ip in intf.neighbors:
                                        neighbor = intf.neighbors[n_ip]
                                        if n_ip != pkt[IP].src:
                                            pkt[pwospfLSU].sequence = neighbor.send_sequence
                                            neighbor.send_sequence += 1
                                            pkt[pwospfLSU].ttl -= 1
                                            pkt[CPUMetadata].origSrcPort = port
                                            pkt[IP].src = intf.ip_address
                                            pkt[IP].dst = neighbor.ip_address
                                            self.send(pkt)

                            # Run Djikstra's algorithm to recompute the forwarding table
                            new_first_hops = self.graph.get_firsts(self.vertex_ind)

                            for i, vertex in enumerate(self.graph.vertex_data):
                                if vertex != 0 and i != self.vertex_ind:
                                    for intf in self.interfaces.values():
                                        if (intf.subnet, intf.mask) == new_first_hops[i]:
                                            port = intf.port
                                            try:
                                                next_hop = list(intf.neighbors.values())[0].ip_address
                                            except IndexError:
                                                next_hop = None
                                            break                                        
                                    try:
                                        matches = [[ip, 32] for ip in vertex[list(vertex.keys())[0]]]
                                    except:
                                        matches = [vertex]
                                    if port and next_hop:
                                        for m in matches:
                                            if tuple(m) not in self.routing:
                                                self.routing[tuple(m)] = (next_hop, port)
                                                self.sw.insertTableEntry(
                                                    table_name='MyIngress.routing',
                                                    match_fields={'hdr.ipv4.dstAddr': m},
                                                    action_name='MyIngress.ipv4_forward',
                                                    action_params={'nextHop': next_hop, 'port': port}
                                                )
                                            else:
                                                # if the route has been updated
                                                if self.routing[tuple(m)] != (next_hop, port):
                                                    self.sw.removeTableEntry(
                                                        table_name='MyIngress.routing',
                                                        match_fields={'': m},
                                                        action_name='MyIngress.ipv4_forward'
                                                    )
                                                    self.sw.insertTableEntry(
                                                        table_name='MyIngress.routing',
                                                        match_fields={'hdr.ipv4.dstAddr': m},
                                                        action_name='MyIngress.ipv4_forward',
                                                        action_params={'nextHop': next_hop, 'port': port}
                                                    )
                                                    self.routing[tuple(m)] = (next_hop, port)

            elif pkt[IP].dst in self.ip_list:  # if the packet is destined for the router, but wasn't pwospf
                pass
                # TODO
            else:  # the packet is here because there is no route for it in the forwarding table or other edge case
                # Drop it
                pass
        # Process ARP packets
        elif ARP in pkt:
            # If the packet is an ARP request 
            if pkt[ARP].op == ARP_OP_REQ:
                # Add the MAC address mapping from the source
                self.addMacAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)
                # If the request came from a PWOSPF interface
                if pkt[CPUMetadata].origSrcPort in self.interfaces.keys():
                    # If the ARP request is actually for this router
                    if pkt[ARP].pdst in self.ip_list:
                        self.send_arp_reply(pkt)
                # If the packet came from a non-PWOSPF interface
                else:
                    # Add the directly connected host
                    self.addLocalRoute(pkt[ARP].psrc, pkt[CPUMetadata].origSrcPort)
                    # Send ARP reply
                    self.send_arp_reply(pkt)
            # If the packet is an ARP reply
            elif pkt[ARP].op == ARP_OP_REPLY:
                # If there are any packets in the waiting queue waiting for this entry
                src = pkt[ARP].psrc
                if src in self.waitingForARP:
                    # Add the MAC address mapping from the reply
                    self.addMacAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)
                    # Send them back to the router
                    for p in self.waitingForARP[src]:
                        p[CPUMetadata].awaitingARP = 0
                        sendp(p, iface=self.controller_iface, verbose=False)
                    self.waitingForARP.pop(src)
                    time.sleep(1)
        else:
            print("Dropped:")
            print(pkt.show())

    # Adds entries to arp table
    def addMacAddr(self, ip, mac):
        if ip not in self.mac_for_ip:
            self.sw.insertTableEntry(
                table_name='MyIngress.arp',
                match_fields={'meta.nextHop': [ip]},
                action_name='MyIngress.set_dst_mac',
                action_params={'dstMac': mac}
            )
            self.mac_for_ip[ip] = mac

    # Adds entries to local table
    def addLocalRoute(self, ip, port):
        if ip in self.ip_list:
            return
        if ip not in self.port_for_local_ip.values():
            self.graph.add_switch_data(ip, self.router_id)
            self.sw.insertTableEntry(
                table_name='MyIngress.local',
                match_fields={'hdr.ipv4.dstAddr': [ip]},
                action_name='MyIngress.forward_local',
                action_params={'dstPort': port}
            ) 
            self.port_for_local_ip[port] = ip

    # Constructs ARP request
    def send_arp_request(self, pkt):
        cpu = CPUMetadata(
                origEtherType=0x0806,
            )
        
        arp = ARP(
                op = ARP_OP_REQ,
                hwsrc = self.mac,
                psrc = self.interfaces[pkt[CPUMetadata].origSrcPort].ip_address,
                pdst = pkt[IP].dst
            )
        
        self.send(Ether() / cpu / arp)

    # Constructs ARP reply
    def send_arp_reply(self, pkt):
        # Build ARP response packet
        pkt[ARP].op = ARP_OP_REPLY
        pkt[ARP].hwdst = pkt[ARP].hwsrc
        pkt[ARP].pdst, pkt[ARP].psrc = pkt[ARP].psrc, pkt[ARP].pdst
        pkt[ARP].hwsrc = self.mac
        
        self.send(pkt)

    def send(self, pkt):
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        
        sendp(pkt, iface=self.controller_iface, verbose=False)
