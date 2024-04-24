import time
from threading import Timer
from p4app import P4Mininet

from controller import Controller
from topologies import RingSwitchTopo, SingleSwitchTopo, TripleSwitchTopo


# Single switch test
def single_sw_test():
    print("############### Begin Single Switch Test ###############")
    topo = SingleSwitchTopo(n=3)

    net = P4Mininet(program="router.p4", topo=topo, auto_arp=False)
    net.start()

    net.get("h2").cmd("ip route add default via 10.0.0.254 dev eth0")
    net.get("h3").cmd("ip route add default via 10.0.0.254 dev eth0")

    cpu = Controller(sw=net.get("s1"), mac="00:00:00:00:01:01", switch_ip="10.0.0.254")
    cpu.start()

    # Test local subnet pings
    print("############### Test local subnet pings")
    h2, h3 = net.get("h2"), net.get("h3")
    print(h2.cmd("arping -c1 10.0.0.3"))
    print(h3.cmd("ping -c1 10.0.0.2"))
    net.get("s1").printTableEntries()


# Triple switch test
def triple_sw_test():
    print("############### Begin Triple Switch Test ###############")
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

    # Test local subnet pings
    print("############### Test local subnet pings")
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

    # Test cross-subnet pings
    print("############### Test cross-subnet subnet pings")
    print(h2.cmd("arping -c1 11.0.0.3"))
    print(h6.cmd("ping -c1 10.0.0.2"))

    print(h2.cmd("arping -c1 12.0.0.2"))
    print(h8.cmd("ping -c1 10.0.0.2"))

    print(h6.cmd("arping -c1 12.0.0.2"))
    print(h8.cmd("ping -c1 11.0.0.3"))

    time.sleep(60)

    # Test interface pings
    print("############### Test interface pings")
    print(h2.cmd("ping -c1 192.168.0.4"))
    print(h6.cmd("ping -c1 192.168.0.0"))
    print(h8.cmd("ping -c1 192.168.0.1"))

    # Test unreachable pings
    print("############### Test unreachable pings")
    print(h2.cmd("ping -c1 192.168.0.10"))
    print(h6.cmd("ping -c1 10.0.0.10"))
    print(h8.cmd("ping -c1 12.0.0.10"))

    time.sleep(60)

    net.get("s1").printTableEntries()
    net.get("s2").printTableEntries()
    net.get("s3").printTableEntries()

def ring_test():
    print("############### Begin Ring Test ###############")
    topo = RingSwitchTopo()

    net = P4Mininet(program="router.p4", topo=topo, auto_arp=False)
    net.start()
    
    net.get("h2").cmd("ip route add default via 10.0.0.254 dev eth0")
    net.get("h3").cmd("ip route add default via 10.0.0.254 dev eth0")
    net.get("h5").cmd("ip route add default via 11.0.0.254 dev eth0")
    net.get("h6").cmd("ip route add default via 11.0.0.254 dev eth0")
    net.get("h8").cmd("ip route add default via 12.0.0.254 dev eth0")
    net.get("h9").cmd("ip route add default via 12.0.0.254 dev eth0")
    net.get("h11").cmd("ip route add default via 13.0.0.254 dev eth0")
    net.get("h12").cmd("ip route add default via 13.0.0.254 dev eth0")

    # Switch 1
    cpu = Controller(
        sw=net.get("s1"),
        mac="00:00:00:00:01:01",
        switch_ip="10.0.0.254",
        interface_ports_ips=[(4, "192.168.0.0", "192.168.0.0", 31), (5, "192.168.0.7", "192.168.0.6", 31)]
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
        interface_ports_ips=[(4, "192.168.0.4", "192.168.0.4", 31), (5, "192.168.0.3", "192.168.0.2", 31)]
    )
    cpu.start()

    # Switch 3
    cpu = Controller(
        sw=net.get("s4"),
        mac="00:00:00:00:01:04",
        switch_ip="13.0.0.254",
        interface_ports_ips=[(4, "192.168.0.5", "192.168.0.4", 31), (5, "192.168.0.6", "192.168.0.6", 31)]
    )
    cpu.start()

    # Test local subnet pings
    print("############### Test local subnet pings")
    h2, h3 = net.get("h2"), net.get("h3")
    print(h2.cmd("arping -c1 10.0.0.3"))
    print(h3.cmd("ping -c1 10.0.0.2"))

    h5, h6 = net.get("h5"), net.get("h6")
    print(h5.cmd("arping -c1 11.0.0.3"))
    print(h6.cmd("ping -c1 11.0.0.2"))

    h8, h9 = net.get("h8"), net.get("h9")
    print(h8.cmd("arping -c1 12.0.0.3"))
    print(h9.cmd("ping -c1 12.0.0.2"))

    h11, h12 = net.get("h11"), net.get("h12")
    print(h11.cmd("arping -c1 13.0.0.3"))
    print(h12.cmd("ping -c1 13.0.0.2"))

    time.sleep(60)

    # Test shortest path pings
    print("############### Test shortest path pings")
    print(h2.cmd("ping -c1 11.0.0.3"))
    print(h6.cmd("ping -c1 10.0.0.2"))

    print(h8.cmd("ping -c1 13.0.0.2"))
    print(h11.cmd("ping -c1 12.0.0.2"))

    # Test flooded path pings
    print("############### Test flooded path pings")
    print(h2.cmd("ping -c1 12.0.0.3"))
    print(h6.cmd("ping -c1 13.0.0.2"))

    time.sleep(60)

    net.get("s1").printTableEntries()
    net.get("s2").printTableEntries()
    net.get("s3").printTableEntries()

def ring_test_with_delay():
    print("############### Begin Ring Test with Delay ###############")
    topo = RingSwitchTopo()

    net = P4Mininet(program="router.p4", topo=topo, auto_arp=False)
    net.start()
    
    net.get("h2").cmd("ip route add default via 10.0.0.254 dev eth0")
    net.get("h3").cmd("ip route add default via 10.0.0.254 dev eth0")
    net.get("h5").cmd("ip route add default via 11.0.0.254 dev eth0")
    net.get("h6").cmd("ip route add default via 11.0.0.254 dev eth0")
    net.get("h8").cmd("ip route add default via 12.0.0.254 dev eth0")
    net.get("h9").cmd("ip route add default via 12.0.0.254 dev eth0")
    net.get("h11").cmd("ip route add default via 13.0.0.254 dev eth0")
    net.get("h12").cmd("ip route add default via 13.0.0.254 dev eth0")

    # Switch 1
    cpu = Controller(
        sw=net.get("s1"),
        mac="00:00:00:00:01:01",
        switch_ip="10.0.0.254",
        interface_ports_ips=[(4, "192.168.0.0", "192.168.0.0", 31), (5, "192.168.0.7", "192.168.0.6", 31)]
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
        interface_ports_ips=[(4, "192.168.0.4", "192.168.0.4", 31), (5, "192.168.0.3", "192.168.0.2", 31)]
    )
    cpu.start()

    # Switch 3
    cpu = Controller(
        sw=net.get("s4"),
        mac="00:00:00:00:01:04",
        switch_ip="13.0.0.254",
        interface_ports_ips=[(4, "192.168.0.5", "192.168.0.4", 31), (5, "192.168.0.6", "192.168.0.6", 31)]
    )
    Timer(70, cpu.start).start()

    # Test local subnet pings
    print("############### Test local subnet pings")
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

    # Test long path pings
    print("############### Test long path pings")
    print(h2.cmd("ping -c1 12.0.0.3"))

    net.get("s1").printTableEntries()
    net.get("s2").printTableEntries()
    net.get("s3").printTableEntries()
    net.get("s4").printTableEntries()

    time.sleep(90)

    # Test short path pings
    print("############### Test short path pings")
    print(h2.cmd("ping -c1 12.0.0.3"))

    net.get("s1").printTableEntries()
    net.get("s2").printTableEntries()
    net.get("s3").printTableEntries()
    net.get("s4").printTableEntries()

# single_sw_test()
# triple_sw_test()
# ring_test()
ring_test_with_delay()