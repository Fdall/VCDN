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


class LinuxRouter( Node ):
	"A Node with IP forwarding enabled."

	def config( self, **params ):
		super( LinuxRouter, self).config( **params )
		# Enable forwarding on the router
		self.cmd( 'sysctl net.ipv4.ip_forward=1' )

	def terminate( self ):
		self.cmd( 'sysctl net.ipv4.ip_forward=0' )
		super( LinuxRouter, self ).terminate()



def myNetwork():
	CONTROLLER_IP = '10.0.2.15'

	net = Mininet(topo=None, build=False, ipBase='10.0.0.0/8')

	info( '*** Adding controller\n' )
	c0=net.addController(name='c0',
					  controller=RemoteController,
					  ip=CONTROLLER_IP,
					  port=6633)

	c1 = net.addController(name='c1', controller=Controller)

	info( '*** Add switches\n')
	os3 = net.addSwitch('os3')
	clu2r1 = net.addSwitch('clu2r1')
	
	


	info( '*** Add hosts\n')
	
	clu2gre = net.addHost('clu2gre', cls=LinuxRouter, ip='30.0.0.1/16')
	or0 = net.addHost('or0', cls=Host, ip='30.0.0.254/16', defaultRoute='via 30.0.0.1')
	http2 = net.addHost('http2', cls=Host, ip='192.168.0.20/24', defaultRoute='via 192.168.0.254')



	info( '*** Add links\n')
	net.addLink(or0, os3)
	net.addLink(os3, clu2gre, params2={ 'ip' : '30.0.0.2/16'})
	
	net.addLink(clu2r1, clu2gre, intfName1=clu2r1.name+'-eth1', params2={ 'ip' : '1.1.1.1/24'})
	net.addLink(os3, clu2r1, intfName2=clu2r1.name+'-eth2')

	net.addLink(http2, clu2r1, intfName2=clu2r1.name+'-eth0')


	# Routage
	print clu2gre.cmd('ip route add default via 1.1.1.254')
	

	info( '*** Starting network\n')
	net.build()

	info( '*** Starting controllers\n')
	for controller in net.controllers:
		controller.start()

	info( '*** Starting switches\n')
	net.get('clu2r1').start([c0])
	net.get('os3').start([c1])


	net.startTerms() 
	CLI(net)
	net.stop()

if __name__ == '__main__':
	setLogLevel( 'info' )
	myNetwork()
