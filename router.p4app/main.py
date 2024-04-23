import time
from p4app import P4Mininet

from controller import Controller
from topologies import SingleSwitchTopo, TripleSwitchTopo


# Single switch test
def single_sw_test():
    topo = SingleSwitchTopo(n=3)

    net = P4Mininet(program="router.p4", topo=topo, auto_arp=False)
    net.start()

    net.get("h2").cmd("ip route add default via 10.0.0.254 dev eth0")
    net.get("h3").cmd("ip route add default via 10.0.0.254 dev eth0")

    cpu = Controller(sw=net.get("s1"), mac="00:00:00:00:01:01", switch_ip="10.0.0.254")
    cpu.start()

    h2, h3 = net.get("h2"), net.get("h3")
    print(h2.cmd("arping -c1 10.0.0.3"))
    print(h3.cmd("ping -c1 10.0.0.2"))
    net.get("s1").printTableEntries()


# Triple switch test
def triple_sw_test():
    topo = TripleSwitchTopo()

    net = P4Mininet(program="router.p4", topo=topo, auto_arp=False)
    net.start()
    
    net.get("h2").cmd("ip route add default via 10.0.0.254 dev eth0")
    net.get("h3").cmd("ip route add default via 10.0.0.254 dev eth0")
    net.get("h5").cmd("ip route add default via 11.0.0.254 dev eth0")
    net.get("h6").cmd("ip route add default via 11.0.0.254 dev eth0")
    net.get("h8").cmd("ip route add default via 12.0.0.254 dev eth0")
    net.get("h9").cmd("ip route add default via 12.0.0.254 dev eth0")

    # Switch 1
    cpu = Controller(
        sw=net.get("s1"),
        mac="00:00:00:00:01:01",
        switch_ip="10.0.0.254",
        interface_ports_ips=[(4, "192.168.0.0", "192.168.0.0", 31), (5, "192.168.0.4", "192.168.0.4", 31)]
    )
    cpu.start()

    # Switch 2
    cpu = Controller(
        sw=net.get("s2"),
        mac="00:00:00:00:01:02",
        switch_ip="11.0.0.254",
        interface_ports_ips=[(4, "192.168.0.1", "192.168.0.0", 31), (5, "192.168.0.2", "192.168.0.2", 31)]
    )
    cpu.start()

    # Switch 3
    cpu = Controller(
        sw=net.get("s3"),
        mac="00:00:00:00:01:03",
        switch_ip="12.0.0.254",
        interface_ports_ips=[(4, "192.168.0.3", "192.168.0.2", 31), (5, "192.168.0.5", "192.168.0.4", 31)]
    )
    cpu.start()

    h2, h3 = net.get("h2"), net.get("h3")
    print(h2.cmd("arping -c1 10.0.0.3"))
    print(h3.cmd("ping -c1 10.0.0.2"))

    h5, h6 = net.get("h5"), net.get("h6")
    print(h5.cmd("arping -c1 11.0.0.3"))
    print(h6.cmd("ping -c1 11.0.0.2"))

    h8, h9 = net.get("h8"), net.get("h9")
    print(h8.cmd("arping -c1 12.0.0.3"))
    print(h9.cmd("ping -c1 12.0.0.2"))

    time.sleep(60)

    net.get("s1").printTableEntries()
    net.get("s2").printTableEntries()
    net.get("s3").printTableEntries()

    h2, h6 = net.get("h2"), net.get("h6")
    print(h2.cmd("arping -c1 11.0.0.3"))
    print(h6.cmd("ping -c1 10.0.0.2"))

    time.sleep(60)

    net.get("s1").printTableEntries()
    net.get("s2").printTableEntries()
    net.get("s3").printTableEntries()

# single_sw_test()
triple_sw_test()
# shortest path test
# late join test
