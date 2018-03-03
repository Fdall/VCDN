#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def myNetwork():
    CONTROLLER_IP = '10.0.2.15'
    H1_IP = '192.168.0.1'
    H2_IP = '192.168.0.2'
    H3_IP = '192.168.0.3'

    net = Mininet(topo=None, build=False, ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    c0=net.addController(name='c0',
                      controller=RemoteController,
                      ip=CONTROLLER_IP,
                      port=6633)

    info( '*** Add switches\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch, protocols='OpenFlow13')
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch, protocols='OpenFlow13')

    info( '*** Add hosts\n')
    h1 = net.addHost('h1', cls=Host, ip=H1_IP, defaultRoute=None)
    h2 = net.addHost('h2', cls=Host, ip=H2_IP, defaultRoute=None)
    h3 = net.addHost('h3', cls=Host, ip=H3_IP, defaultRoute=None)

    info( '*** Add links\n')
    net.addLink(s1, h1, 1, 1)
    net.addLink(s2, h2, 2, 2)
    net.addLink(s3, h3, 3, 3)

    net.addLink(s1, s2, 2, 1)
    net.addLink(s1, s3, 3, 1)
    net.addLink(s2, s3, 3, 2)

    info( '*** Starting network\n')
    net.build()

    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s1').start([c0])
    net.get('s2').start([c0])
    net.get('s3').start([c0])

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

