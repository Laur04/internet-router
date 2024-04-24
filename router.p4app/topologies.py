from mininet.topo import Topo


# One switch that connects N hosts
class SingleSwitchTopo(Topo):
    def __init__(self, n):
        Topo.__init__(self)

        switch = self.addSwitch("s1")

        for i in range(1, n + 1):
            host = self.addHost(
                "h%d" % i,
                ip="10.0.0.%d" % i,
                mac="00:00:00:00:00:%02x" % i
            )
            self.addLink(host, switch, port2=i)

# Three switches, with three hosts each
class TripleSwitchTopo(Topo):
    def __init__(self):
        Topo.__init__(self)

        switches = []
        # Add 3 hosts to each switch on ports 1-3
        for s in ["s1", "s2", "s3"]:
            switch = self.addSwitch(s)
            switches.append(switch)

        host = self.addHost("h1", ip="10.0.0.1", mac="00:00:00:00:00:01")
        self.addLink(host, switches[0], port2=1)
        host = self.addHost("h2", ip="10.0.0.2", mac="00:00:00:00:00:02")
        self.addLink(host, switches[0], port2=2)
        host = self.addHost("h3", ip="10.0.0.3", mac="00:00:00:00:00:03")
        self.addLink(host, switches[0], port2=3)

        host = self.addHost("h4", ip="11.0.0.1", mac="00:00:00:00:00:04")
        self.addLink(host, switches[1], port2=1)
        host = self.addHost("h5", ip="11.0.0.2", mac="00:00:00:00:00:05")
        self.addLink(host, switches[1], port2=2)
        host = self.addHost("h6", ip="11.0.0.3", mac="00:00:00:00:00:06")
        self.addLink(host, switches[1], port2=3)

        host = self.addHost("h7", ip="12.0.0.1", mac="00:00:00:00:00:07")
        self.addLink(host, switches[2], port2=1)
        host = self.addHost("h8", ip="12.0.0.2", mac="00:00:00:00:00:08")
        self.addLink(host, switches[2], port2=2)
        host = self.addHost("h9", ip="12.0.0.3", mac="00:00:00:00:00:09")
        self.addLink(host, switches[2], port2=3)

        # Connect port 4 on s1 to port 4 on s2
        self.addLink(switches[0], switches[1], port1=4, port2=4)

        # Connect port 5 on s1 to port 5 on s3
        self.addLink(switches[0], switches[2], port1=5, port2=5)

        # Connect port 5 on s2 to port 4 on s3
        self.addLink(switches[1], switches[2], port1=5, port2=4)# Three switches, with three hosts each

# Four switches, with three hosts each
class RingSwitchTopo(Topo):
    def __init__(self):
        Topo.__init__(self)

        switches = []
        # Add 3 hosts to each switch on ports 1-3
        for s in ["s1", "s2", "s3", "s4"]:
            switch = self.addSwitch(s)
            switches.append(switch)

        host = self.addHost("h1", ip="10.0.0.1", mac="00:00:00:00:00:01")
        self.addLink(host, switches[0], port2=1)
        host = self.addHost("h2", ip="10.0.0.2", mac="00:00:00:00:00:02")
        self.addLink(host, switches[0], port2=2)
        host = self.addHost("h3", ip="10.0.0.3", mac="00:00:00:00:00:03")
        self.addLink(host, switches[0], port2=3)

        host = self.addHost("h4", ip="11.0.0.1", mac="00:00:00:00:00:04")
        self.addLink(host, switches[1], port2=1)
        host = self.addHost("h5", ip="11.0.0.2", mac="00:00:00:00:00:05")
        self.addLink(host, switches[1], port2=2)
        host = self.addHost("h6", ip="11.0.0.3", mac="00:00:00:00:00:06")
        self.addLink(host, switches[1], port2=3)

        host = self.addHost("h7", ip="12.0.0.1", mac="00:00:00:00:00:07")
        self.addLink(host, switches[2], port2=1)
        host = self.addHost("h8", ip="12.0.0.2", mac="00:00:00:00:00:08")
        self.addLink(host, switches[2], port2=2)
        host = self.addHost("h9", ip="12.0.0.3", mac="00:00:00:00:00:09")
        self.addLink(host, switches[2], port2=3)

        host = self.addHost("h10", ip="13.0.0.1", mac="00:00:00:00:00:10")
        self.addLink(host, switches[3], port2=1)
        host = self.addHost("h11", ip="13.0.0.2", mac="00:00:00:00:00:11")
        self.addLink(host, switches[3], port2=2)
        host = self.addHost("h12", ip="13.0.0.3", mac="00:00:00:00:00:12")
        self.addLink(host, switches[3], port2=3)

        # Connect port 4 on s1 to port 4 on s2
        self.addLink(switches[0], switches[1], port1=4, port2=4)

        # Connect port 5 on s2 to port 5 on s3
        self.addLink(switches[1], switches[2], port1=5, port2=5)

        # Connect port 4 on s3 to port 4 on s4
        self.addLink(switches[2], switches[3], port1=4, port2=4)

        # Connect port 5 on s4 to port 5 on s1
        self.addLink(switches[3], switches[0], port1=5, port2=5)
