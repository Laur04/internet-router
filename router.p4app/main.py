import time
from p4app import P4Mininet

from controller import Controller
from topologies import SingleSwitchTopo, TripleSwitchTopo


# Single switch test
def single_sw_test():
    num_hosts = 3
    topo = SingleSwitchTopo(n=num_hosts)
    switches = ["s1"]

    net = P4Mininet(program="router.p4", topo=topo, auto_arp=False)
    net.start()

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

    # Switch 1
    cpu = Controller(
        sw=net.get("s1"),
        mac="00:00:00:00:01:01",
        switch_ip="10.0.0.254",
        interface_ports_ips=[(4, "192.168.0.0", "192.168.0.0", 31), (5, "192.168.0.1", "192.168.0.0", 31)]
    )
    cpu.start()

    # Switch 2
    cpu = Controller(
        sw=net.get("s2"),
        mac="00:00:00:00:01:02",
        switch_ip="11.0.0.254",
        interface_ports_ips=[(4, "192.168.0.2", "192.168.0.2", 31), (5, "192.168.0.3", "192.168.0.2", 31)]
    )
    cpu.start()

    # Switch 1
    cpu = Controller(
        sw=net.get("s3"),
        mac="00:00:00:00:01:03",
        switch_ip="12.0.0.254",
        interface_ports_ips=[(4, "192.168.0.4", "192.168.0.4", 31), (5, "192.168.0.5", "192.168.0.4", 31)]
    )
    cpu.start()

    h2, h3 = net.get("h2"), net.get("h3")
    print(h2.cmd("arping -c1 10.0.0.3"))
    print(h3.cmd("ping -c1 10.0.0.2"))

    net.get("s1").printTableEntries()
    
    time.sleep(40)

    net.get("s1").printTableEntries()


# single_sw_test()
triple_sw_test()
