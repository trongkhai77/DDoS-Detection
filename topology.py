#!/usr/bin/python
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call
import time

def serviceNetwork():
    net = Mininet(topo=None,
                  build=False,
                  ipBase='10.0.0.0/8',
                  link=TCLink)

    info('*** Adding controller\n')
    c0 = net.addController(name='c0',
                          controller=RemoteController,
                          ip='127.0.0.1',
                          protocol='tcp',
                          port=6633)

    info('*** Adding switches\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch)
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch)
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch)

    info('*** Adding hosts and servers\n')
    # Using CPULimitedHost for better resource control
    h1 = net.addHost('h1', cls=CPULimitedHost, ip='10.0.0.1', cpu=.2)
    h2 = net.addHost('h2', cls=CPULimitedHost, ip='10.0.0.2', cpu=.2)
    h3 = net.addHost('h3', cls=CPULimitedHost, ip='10.0.0.3', cpu=.2)
    h4 = net.addHost('h4', cls=CPULimitedHost, ip='10.0.0.4', cpu=.2)
    ws1 = net.addHost('ws1', cls=CPULimitedHost, ip='10.0.0.10', cpu=.5)
    db1 = net.addHost('db1', cls=CPULimitedHost, ip='10.0.0.20', cpu=.5)
    
    info('*** Adding attackers\n')
    attacker1 = net.addHost('attacker1', cls=CPULimitedHost, ip='10.0.0.100', cpu=.1)
    attacker2 = net.addHost('attacker2', cls=CPULimitedHost, ip='10.0.0.101', cpu=.1)
    attacker3 = net.addHost('attacker3', cls=CPULimitedHost, ip='10.0.0.102', cpu=.1)

    info('*** Creating links\n')
    # Links between switches with QoS
    net.addLink(s1, s2, bw=20, delay='5ms', max_queue_size=1000)
    net.addLink(s2, s3, bw=20, delay='5ms', max_queue_size=1000)
    net.addLink(s3, s4, bw=20, delay='5ms', max_queue_size=1000)
    net.addLink(s4, s1, bw=20, delay='5ms', max_queue_size=1000)

    # Links to regular hosts with QoS
    net.addLink(h1, s1, bw=15, delay='2ms', loss=1, max_queue_size=500)
    net.addLink(h2, s2, bw=15, delay='2ms', loss=1, max_queue_size=500)
    net.addLink(h3, s3, bw=15, delay='2ms', loss=1, max_queue_size=500)
    net.addLink(h4, s4, bw=15, delay='2ms', loss=1, max_queue_size=500)
    
    # Links to servers with better QoS
    net.addLink(ws1, s1, bw=20, delay='1ms', max_queue_size=1000)
    net.addLink(db1, s2, bw=20, delay='1ms', max_queue_size=1000)
    
    # Links to attackers with strict rate limiting
    net.addLink(attacker1, s3, bw=5, delay='10ms', max_queue_size=100)
    net.addLink(attacker2, s4, bw=5, delay='10ms', max_queue_size=100)
    net.addLink(attacker3, s3, bw=5, delay='10ms', max_queue_size=100)

    info('*** Starting network\n')
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])
    s4.start([c0])

    info('*** Waiting for controller startup\n')
    time.sleep(5)

    # Configure OpenFlow 1.3
    for switch in [s1, s2, s3, s4]:
        switch.cmd('ovs-vsctl set Bridge {} protocols=OpenFlow13'.format(switch.name))

    info('*** Configuring Flow Rules\n')
    
    # Basic flow rules with rate limiting
    for switch in [s1, s2, s3, s4]:
        # Default flow to controller with rate limiting
        switch.cmd('ovs-ofctl add-flow {} "priority=0,actions=CONTROLLER:65535"'.format(switch.name))
        # ARP handling with rate limiting
        switch.cmd('ovs-ofctl add-flow {} "priority=100,arp,actions=NORMAL"'.format(switch.name))
        # Rate limiting for ICMP
        switch.cmd('ovs-ofctl add-flow {} "priority=200,icmp,actions=meter:1,NORMAL"'.format(switch.name))
        # Configure meter for rate limiting
        switch.cmd('ovs-ofctl -O OpenFlow13 add-meter {} "meter=1 pktps=1000 burst_size=100"'.format(switch.name))

    # Enhanced security rules for web and database servers
    s1.cmd('ovs-ofctl add-flow s1 "priority=1000,tcp,nw_dst=10.0.0.10,tcp_dst=80,actions=meter:2,output:5"')
    s1.cmd('ovs-ofctl -O OpenFlow13 add-meter s1 "meter=2 pktps=2000 burst_size=200"')
    
    s2.cmd('ovs-ofctl add-flow s2 "priority=1000,tcp,nw_dst=10.0.0.20,tcp_dst=3306,actions=meter:3,output:5"')
    s2.cmd('ovs-ofctl -O OpenFlow13 add-meter s2 "meter=3 pktps=1000 burst_size=100"')

    # DDoS protection rules
    for switch in [s1, s2, s3, s4]:
        # Rate limit TCP SYN packets
        switch.cmd('ovs-ofctl add-flow {} "priority=500,tcp,tcp_flags=syn,actions=meter:4,NORMAL"'.format(switch.name))
        switch.cmd('ovs-ofctl -O OpenFlow13 add-meter {} "meter=4 pktps=100 burst_size=50"'.format(switch.name))
        
        # Drop invalid TCP flags combinations
        switch.cmd('ovs-ofctl add-flow {} "priority=600,tcp,tcp_flags=syn+fin,actions=drop"'.format(switch.name))
        switch.cmd('ovs-ofctl add-flow {} "priority=600,tcp,tcp_flags=syn+rst,actions=drop"'.format(switch.name))

    info('*** Configuring Web Server\n')
    ws1.cmd('python -m SimpleHTTPServer 80 &')

    info('*** Testing connectivity\n')
    net.pingAll()

    # Additional security configurations for hosts
    for host in [h1, h2, h3, h4, ws1, db1]:
        # Enable SYN cookies
        host.cmd('sysctl -w net.ipv4.tcp_syncookies=1')
        # Increase backlog queue
        host.cmd('sysctl -w net.ipv4.tcp_max_syn_backlog=2048')
        # Enable source validation
        host.cmd('sysctl -w net.ipv4.conf.all.rp_filter=1')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    serviceNetwork()