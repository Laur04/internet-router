from scapy.fields import ByteField, IntField, ShortField, SignedLongField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP, SourceIPField
from scapy.layers.l2 import Ether, ARP


TYPE_CPU_METADATA = 0x080a

class CPUMetadata(Packet):
    name = "CPUMetadata"
    fields_desc = [
        ShortField("origEtherType", None),
        ShortField("origSrcPort", 0),
        ByteField("awaitingARP", 0),
    ]

bind_layers(Ether, CPUMetadata, type=TYPE_CPU_METADATA)
bind_layers(CPUMetadata, IP, origEtherType=0x0800)
bind_layers(CPUMetadata, ARP, origEtherType=0x0806)

class pwospfHeader(Packet):
    name = "pwospfHeader"
    fields_desc = [
        ByteField("version", 0x02),
        ByteField("type", None),
        ShortField("packetLength", None),
        SourceIPField("routerID", None),
        IntField("areaID", None),
        ShortField("checksum", None),
        ShortField("autype", 0),
        SignedLongField("authentication", 0),
    ]

bind_layers(IP, pwospfHeader, proto=89)

class pwospfHello(Packet):
    name = "pwospfHello"
    fields_desc = [
        IntField("networkMask", None),
        ShortField("helloInt", None),
        ShortField("padding", 0),
    ]

bind_layers(pwospfHeader, pwospfHello, type=1)

class pwospfLSU(Packet):
    name = "pwospfLSU"
    fields_desc = [
        ShortField("sequence", None),
        ShortField("ttl", None),
        IntField("numAdvertisements", None),
    ]

bind_layers(pwospfHeader, pwospfLSU, type=4)

class pwospfLink(Packet):
    name = "pwospfLink"
    fields_desc = [
        SourceIPField("subnet", None),
        IntField("mask", None),
        SourceIPField("routerID", None),
    ]

bind_layers(pwospfLSU, pwospfLink)
bind_layers(pwospfLink, pwospfLink)

class Interface():
    def __init__(self, ip_address, subnet, mask, port, hello_int):
        self.ip_address = ip_address
        self.subnet = subnet
        self.mask = mask
        self.port = port
        self.hello_int = hello_int
        self.neighbors = dict()

class Neighbor():
    def __init__(self, ip_address, rid, time):
        self.ip_address = ip_address
        self.rid = rid
        self.last_seen = time
        self.send_sequence = 0
        self.rec_sequence = 0

class Graph:
    def __init__(self):
        self.current_size = 0
        self.size = 64  # setting initial size of 64x64
        self.adj_matrix = [[0] * self.size for _ in range(self.size)]
        self.time_matrix = [[0] * self.size for _ in range(self.size)]
        self.vertex_data = [0 for _ in range(self.size)]

    def add_edge(self, u, v, rid, update_time):
        updated = False
        if 0 <= u < self.size and 0 <= v < self.size:
            if not (self.adj_matrix[u][v] == self.adj_matrix[v][u] == rid):
                self.adj_matrix[u][v] = rid
                self.adj_matrix[v][u] = rid
                updated = True
            if not (self.time_matrix[u][v] == self.time_matrix[v][u] == update_time):
                self.time_matrix[u][v] = update_time
                self.time_matrix[v][u] = update_time
                updated = True
            return updated

    def connect_range(self, rid, vertex, start=None, stop=None):
        if start is None:
            start = 0
        if stop is None:
            stop = self.current_size
        for u in range(start, stop):
            self.add_edge(u, vertex, rid, -1)

    def add_vertex_data(self, data):
        # Try to find existing entry and return its index
        for i, sw in enumerate(self.vertex_data):
            try:
                if data == sw:
                    return i, False
            except:
                pass
        # If there is no existing entry add one and return its index
        self.vertex_data[self.current_size] = data
        self.current_size += 1
        return self.current_size - 1, True

    def add_switch_data(self, data, rid):
        # Try to find existing entry and return its index
        for i, sw in enumerate(self.vertex_data):
            try:
                if rid in sw.keys():
                    sw[rid].append(data)
                    return i, False
            except:
                pass
        # If there is no existing entry add one and return its index
        self.vertex_data[self.current_size] = {rid: data}
        self.current_size += 1
        return self.current_size - 1, True
    
    def dijkstra(self, start_vertex):
        distances = [float('inf')] * self.size
        predecessors = [None] * self.size
        distances[start_vertex] = 0
        visited = [False] * self.size

        for _ in range(self.size):
            min_distance = float('inf')
            u = None
            for i in range(self.size):
                if not visited[i] and distances[i] < min_distance:
                    min_distance = distances[i]
                    u = i

            if u is None:
                break

            visited[u] = True

            for v in range(self.size):
                if self.adj_matrix[u][v] != 0 and not visited[v]:
                    alt = distances[u] + 1
                    if alt < distances[v]:
                        distances[v] = alt
                        predecessors[v] = u

        return distances, predecessors

    def get_firsts(self, start_ind):
        distances, predecessors = self.dijkstra(start_ind)
        first_hops = []
        for i, _ in enumerate(distances):
            first = None
            current = i
            while current is not None:
                first = self.vertex_data[current]
                current = predecessors[current]
                if current == start_ind:
                    break
            first_hops[i] = first
        return first_hops
