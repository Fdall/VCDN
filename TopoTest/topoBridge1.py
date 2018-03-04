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
	
	CLIENT1_IP = '10.1.0.1/16'
	CLIENT2_IP = '30.0.0.1/16'

	net = Mininet(topo=None, build=False, ipBase='10.0.0.0/8')

	info( '*** Adding controller\n' )
	c0=net.addController(name='c0',
					  controller=RemoteController,
					  ip=CONTROLLER_IP,
					  port=6633)


	## Simple switch controller
	c1 = net.addController(name='c1', controller=Controller)

	info( '*** Add switches\n')
	sb1 = net.addSwitch('sb1')
	os2 = net.addSwitch('os2')
	b1 = net.addSwitch('b1')
	
	


	info( '*** Add hosts\n')
	
	# Routers
	b1gre1 = net.addHost('b1gre1', cls=LinuxRouter, ip='1.1.1.254/16')
	b1gre2 = net.addHost('b1gre2', cls=LinuxRouter, ip='1.1.1.254/16')
	or0 = net.addHost('or0', cls=LinuxRouter, ip='20.0.0.254/8')
	
	client1 = net.addHost('client1', cls=Host, ip=CLIENT1_IP, defaultRoute='via 10.1.0.254')
	client2 = net.addHost('client2', cls=Host, ip=CLIENT2_IP, defaultRoute='via 30.0.0.254')



	info( '*** Add links\n')
	net.addLink(b1, b1gre1, intfName1=b1.name+'-gre1', params2={ 'ip' : '1.1.1.254/24'})
	net.addLink(b1, b1gre2, intfName1=b1.name+'-gre2', params2={ 'ip' : '1.1.1.254/24'})
	
	net.addLink(os2, b1gre1, params2={ 'ip' : '20.1.0.1/8'})
	net.addLink(os2, b1gre2, params2={ 'ip' : '20.1.0.2/8'})
	
	net.addLink(sb1, b1, intfName2=b1.name+'-eth0')
	net.addLink(sb1, client1)
	
	net.addLink(os2, or0, params2={ 'ip' : '20.0.0.254/8'})
	net.addLink(client2, or0, params2={ 'ip' : '30.0.0.254/8'})
	net.addLink(sb1, or0, params2={ 'ip' : '10.1.0.200/16'})
	
	
	# Routes
	print b1gre1.cmd('ip route add default via 20.0.0.254')
	print b1gre2.cmd('ip route add default via 20.0.0.254')




	info( '*** Starting network\n')
	net.build()

	info( '*** Starting controllers\n')
	for controller in net.controllers:
		controller.start()

	info( '*** Starting switches\n')
	net.get('b1').start([c0])
	net.get('sb1').start([c1])
	net.get('os2').start([c1])

	net.startTerms() 
	CLI(net)
	net.stop()

if __name__ == '__main__':
	setLogLevel( 'info' )
	myNetwork()
