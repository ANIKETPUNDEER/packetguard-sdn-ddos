"""4-switch tree: twelve normal hosts and four reserved attack hosts."""
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.topo import Topo


class PacketGuardTopo(Topo):
    def build(self):
        root = self.addSwitch("s1", protocols="OpenFlow13")
        leaves = [self.addSwitch(f"s{i}", protocols="OpenFlow13") for i in (2, 3, 4)]
        for leaf in leaves:
            self.addLink(root, leaf, cls=TCLink, bw=1000, delay="2ms")
        # 12 legitimate endpoints, distributed evenly across the leaf switches.
        for i in range(1, 13):
            leaf = leaves[(i-1)//4]
            host = self.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
            # A 20 Mbps h1 access link makes the bounded 10 Mbps aggregate
            # UDP workload create measurable contention in the control setup.
            access_bw = 20 if i == 1 else 1000
            self.addLink(host, leaf, cls=TCLink, bw=access_bw, delay="2ms")
        # Reserved range is disjoint from benign hosts and is the scope for
        # aggregate containment rules installed by the controller.
        for offset in range(4):
            i = 201 + offset
            leaf = leaves[offset % len(leaves)]
            host = self.addHost(f"a{offset+1}", ip=f"10.0.0.{i}/24")
            # A 20 Mbps h1 access link makes the bounded 10 Mbps aggregate
            # UDP workload create measurable contention in the control setup.
            access_bw = 20 if i == 1 else 1000
            self.addLink(host, leaf, cls=TCLink, bw=access_bw, delay="2ms")


def main():
    setLogLevel("info")
    topo = PacketGuardTopo()
    net = Mininet(topo=topo, controller=None, link=TCLink,
                  switch=OVSKernelSwitch, autoSetMacs=True, autoStaticArp=True)
    net.addController("c0", controller=RemoteController,
                      ip="127.0.0.1", port=6653)
    info("*** Starting PacketGuard 4-switch / 16-host lab\n")
    net.start()
    for switch in net.switches:
        switch.cmd("ovs-vsctl set bridge %s protocols=OpenFlow13" % switch.name)
    info("*** Controller: 127.0.0.1:6653; reserved attack prefix: 10.0.0.192/28\n")
    info("*** Run pingall for reachability. Exit this CLI before launching experiments/run_lab.py.\n")
    CLI(net)
    net.stop()


if __name__ == "__main__":
    main()

