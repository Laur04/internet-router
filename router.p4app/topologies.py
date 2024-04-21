# Initializes various mininet topologies 

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

class TripleSwitchTopo(Topo):
    def __init__(self):
        Topo.__init__(self)

        switches = []
        # Add 3 hosts to each switch on ports 1-3
        for sNum, s in enumerate(["s1", "s2", "s3"]):
            switch = self.addSwitch(s)
            switches.append(switch)

            for i in range(1, 4):
                hostNum = (sNum * 3) + i
                host = self.addHost(
                    "h%d" % hostNum,
                    ip="%d.0.0.%d" % (sNum + 10, i),
                    mac="00:00:00:00:00:%02x" % hostNum
                )
                self.addLink(host, switch, port2=i)

        # Connect port 4 on s1 to port 4 on s2
        self.addLink(switches[0], switches[1], port1=4, port2=4)

        # Connect port 5 on s1 to port 5 on s3
        self.addLink(switches[0], switches[2], port1=5, port2=5)

        # Connect port 5 on s2 to port 4 on s3
        self.addLink(switches[1], switches[2], port1=5, port2=4)
