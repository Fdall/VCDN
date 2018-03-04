#!/usr/bin/python

"""
Create a network where different switches are connected to
different controllers, by creating a custom Switch() subclass.
"""

import inspect, traceback, os

from mininet.net import Mininet
from mininet.node import OVSSwitch, Controller, RemoteController, Host, DefaultController, Ryu, Node
from mininet.topolib import TreeTopo
from mininet.log import setLogLevel
from mininet.cli import CLI

from mininet.term import makeTerms, makeTerm
from mininet.log import setLogLevel, info

from mininet.link import Intf

from mininet.moduledeps import pathCheck


setLogLevel( 'info' )


### Custom Nodes ###

class CustomHost( Host ):
	
	def __init__(self, *args, **kwargs):
		Host.__init__(self, *args, **kwargs)
		self.popenTerms = []
	
	def configDefault(self, **kwargs):
		Host.configDefault(self, **kwargs)
				
		# Set IP to the default interface
		if 'ip' in self.params and self.params.get('ip'):
			ip_prefix = self.params.get( 'ip' )
			[ip, prefix] = ip_prefix.split('/')
			
			self.setIP(ip, prefix)
		
		
	
	def bashTerm(self, title='', bashCmdsList=[]):
		if isinstance(title, list):
			bashCmdsList = title
			title = ''
		
		# Title of the terminal
		title = self.name+': '+title
		
		# Keep open terminal at the end of cmds
		bashCmdsList.append('bash')
		
		# Cmd to launch bash
		bashCmd = ['bash', '-c', '; '.join(bashCmdsList)]
	
		# Cmd to open new terminal and execut bash
		xtermCmd = ['xterm', '-title', title, '-e'] + bashCmd
		gtermCmd = ['dbus-launch gnome-terminal', '--title', title, '-e'] + bashCmd
		#~ urxvtCmd = ['urxvt', '-title', title, '-e'] + bashCmd
		
		#~ print(' '.join(gtermCmd))
		
		# Execute cmd in new process
		popen = self.popen(xtermCmd)
		
		# Save the popen
		self.popenTerms.append(popen)
		
		return popen
		
	def terminate(self):
		# Close all open terminals
		for popen in self.popenTerms:
			popen.terminate()
		
		Host.terminate(self)





class HttpServer( CustomHost ):
	
	def config(self, **params):
		super( HttpServer, self).config( **params )
		#~ CustomHost.configDefault(self, **params)
		
		try:
			ip = self.IP()
		except:
			ip = '127.0.0.1'
		
		# Run server in terminal
		bashCmds = [
			'cd ./http_server/',
			'python ./webserver2.py '+ip+' 80'
		]
		self.termPopen = self.bashTerm('httpServer', bashCmds)




class LinuxRouter( Node ):
	"A Node with IP forwarding enabled."

	def config( self, **params ):
		super( LinuxRouter, self).config( **params )
		# Enable forwarding on the router
		self.cmd( 'sysctl net.ipv4.ip_forward=1' )

	def terminate( self ):
		self.cmd( 'sysctl net.ipv4.ip_forward=0' )
		super( LinuxRouter, self ).terminate()






### Custom controller ###

class OpenFlowNetwork():
	def __init__( self, mininet=Mininet(), controller=None):
		self.mininet = mininet
		if controller:
			#~ self.mininet.addController( controller)
			self.controllers = [controller]
		else:
			self.controllers = [mininet.defaultController]

	def addController(self, controller):
		# Add a network controller
		self.controllers.append(controller)
		return controller
		
	def addSwitch(self, name, cls=OVSSwitch, *args, **kwargs):
		controllers = self.controllers

		class OpenFlowSwitch( cls ):
			"Controler for border switches"
			def start( self, defaultControllersNotUsed ):
				# Assign controllers on the switch start
				return super(OpenFlowSwitch, self).start( controllers )
				#~ return OVSSwitch.start( self, defaultControllersNotUsed )
		
		# New switch with associated controllers		
		return self.mininet.addSwitch(name, OpenFlowSwitch, *args, **kwargs)





class CustomRyu( Ryu, CustomHost ):
	
	def __init__(self, name, path=None, **kwargs):
		Ryu.__init__(self, name, path, **kwargs)
		self.popenTerms = []
	
	def start(self):
		"""Start <controller> <args> on controller.
           Log to /tmp/cN.log"""
		cmds = []
		
		pathCheck( self.command )
		
		if self.cdir is not None:
			cmds.append( 'cd ' + self.cdir )
		cmds.append( self.command + ' ' + self.cargs % self.port)
		
		# Execute cmd
		self.bashTerm('RyuController', cmds)
		
		self.execed = False
		




class CustomBridge( OVSSwitch ):
	def __init__(self, name, **kwargs):
		OVSSwitch.__init__(self, name, batch=True, **kwargs)
		
	
	def attachGre(self, intfName, remoteIp, key=None):
		if key:
			self.vsctl('--', 'set', 'interface', intfName, 'type=gre', 'options:remote_ip='+remoteIp, 'options:key=%d' % key, 'options:dev=border_s5-eth2')
		else:
			self.vsctl('--', 'set', 'interface', intfName, 'type=gre', 'options:remote_ip='+remoteIp, 'options:dev=border_s5-eth2')


	def showConf(self):
		print('not')

	def start(self, controllers):
		cmds = self.commands
		self.commands = []
		OVSSwitch.start(self, controllers)
		self.commands = self.commands + cmds




### Cluster ###

class Surrogate( OVSSwitch ):
	
	def __init__(self, name, mininet=None, **args):
		OVSSwitch.__init__(self, name, **args)
		self.mininet = mininet
		self.servers = []
	
	
	
	def addServer(self, name, ip=None):
		name = name if name else 'http%d' % len(self.servers)
	
	
		# New host to support the server
		host = self.mininet.addHost( name, HttpServer, ip=ip, defaultRoute='via 192.168.0.254' )
		
		
		# Link server with surrogate
		self.mininet.addLink(self, host)
				
		
		# Store server
		self.servers.append(host)
		
		
		return host


	def start(self, defaultControllersNotUsed):
		return super(Surrogate, self).start( [self.mininet.defaultController] )

		
class Cluster():
	
	def __init__(self, mininet=Mininet(), name='clus', controller=None):
		self.mininet = mininet
		self.surrogates = []
		self.router = None
		self.greRouter = None
		self.name = name
		
		## Network connected around a central switch (debug with wireshark)
		self.centralSwitch = self.mininet.addSwitch(self.name+'cs0')
		
		
		## Controller for routers
		self.network = OpenFlowNetwork(self.mininet, controller)
		
		self.addRouter()
		
		
	def addRouter(self, name=None, dpid=None, **kwargs):
		# Only one router ######################
		#~ if len(self.routers):
			#~ raise NameError('Only one router')
		#########################################
		
		## ID of element in controller
		dpid = str(dpid) if dpid else str(self.nextDpid())
		name = name if name else 'r'+dpid
		
		
		
		### New router
		# Router associated with controller in cluster constructor
		#~ router = self.network.addSwitch(self.name+'_'+name, dpid=dpid, cls=CustomBridge, **kwargs)
		
		### Test with Linux ROUTER #### 
		router = self.mininet.addHost(self.name+name, cls=LinuxRouter, ip='192.168.0.254/24' )
		
		# Link router with central switch
		self.mininet.addLink(self.centralSwitch, router, intfName2=router.name+'-eth0', params2={ 'ip' : '192.168.0.254/24' })
		
		# Store router
		self.router = router
		
		
		
		### New tunnel router
		greRouter = self.mininet.addHost(self.name+'gre', cls=LinuxRouter, ip='1.1.1.1/24' )
		
		# Link with router
		self.mininet.addLink(greRouter, router, intfName1=greRouter.name+'-eth0', intfName2=router.name+'-eth1', params1={ 'ip' : '1.1.1.1/24' }, params2={ 'ip' : '1.1.1.254/24' })

		# Default gateway
		greRouter.cmd('ip route add default via 1.1.1.254')

		# Store
		self.greRouter = greRouter
		
		
		return router
		
		
	def addSurrogate(self, name=None, dpid=None):
		name = name if name else 's%d' % len(self.surrogates)
		
		
		### New surrogate
		# Default Hub switch
		switch = self.mininet.addSwitch(self.name+name, Surrogate, dpid=dpid, mininet=self.mininet)
		
		# Link with central switch
		self.mininet.addLink(switch, self.centralSwitch)
		
		# Store surrogate
		self.surrogates.append(switch)
		
		
		return switch


	def nextDpid(self):
		dpid = len(self.surrogates)
		if self.centralSwitch is not None:
			dpid = dpid+1
		if self.router is not None:
			dpid = dpid+1
		return dpid




### Global network ###

class CDN():
	
	def __init__( self, mininet=Mininet(), controller=None ):
		self.mininet = mininet
		self.bridges = []
		self.clusters = []
		
		
		# New openFlowNetwork for border switches
		border_network = OpenFlowNetwork( self.mininet, controller)
		
		
		###### OVERLAY ######
		# Create central router
		or0 = mininet.addHost( 'or0', cls=LinuxRouter, ip='20.0.0.254/8' ) #First IP linked
		
		
		
		## Network 20.0.0.0
		os2 = mininet.addSwitch('os2')
		
		
		
		## Network 30.0.0.0
		os3 = mininet.addSwitch('os3')
		
		
		
		## Links
		mininet.addLink(os2, or0, params2={ 'ip' : '20.0.0.254/8' } )
		mininet.addLink(os3, or0, params2={ 'ip' : '30.0.0.254/8' } )
		
		
		
		# Store equipements
		self.or0 = or0
		self.os2 = os2
		self.os3 = os3
		self.border_network = border_network
		
		
		
	def addBorderNetwork( self, networkId=None):
		
		###### New border network 10.X.0.0 #######
		networkId = networkId if networkId else len(self.bridges)+1
		# Network ip is 10.id.0.0/16
		
		
		
		### New bridge
		bridgeName = 'b%d' % networkId
		# With controller of CDN constructor
		#~ newBridge = self.border_network.addSwitch(bridgeName, CustomBridge )
		
		### Test with Linux ROUTER #### 
		bridge = self.mininet.addHost(bridgeName, cls=LinuxRouter, ip='10.%d.0.254/16' % networkId )
		
		
		
		# Create switch for multiple entries
		switchName = 'sb%d' % networkId
		switch = self.mininet.addSwitch(switchName)

		self.mininet.addLink(switch, bridge, intfName2=bridgeName+'-eth0')
		
		
		# Link local network with overlay
		self.mininet.addLink(switch, self.or0, params2={ 'ip' : '10.%d.0.200/16' % networkId })


		# Store bridge
		self.bridges.append(bridge)
		

		### Network 20.0.0.0 ###
		# Link with clusters
		for cluster in self.clusters:
			self.linkBridgeCluster(bridge, cluster)
		

		return switch
		
		
	def addCluster( self, controller=None ):
		# Id to auto generate http port ???
		clusterId = len(self.clusters)+1
		clusterName = 'clu%d' % clusterId
		
		
		### New cluster ###
		cluster = Cluster(self.mininet, clusterName, controller)
		
		# Default create router in cluster
		router = cluster.router
		greRouter = cluster.greRouter
		
		## Connect cluster to overlay for output router + greRouter
		# Connect router
		self.mininet.addLink(self.os3, router, intfName2=router.name+'-eth2', params2={ 'ip' : '30.0.0.10%d/8' % clusterId })
		
		### Test with Linux ROUTER #### 
		router.cmd('ip route add default via 30.0.0.254')

		# Connect greRouter
		self.mininet.addLink(self.os3, greRouter, intfName2=greRouter.name+'-eth1', params2={ 'ip' : '30.0.0.%d/8' % clusterId })
		
		# Store cluster
		self.clusters.append(cluster)
		
		
		
		
		### Create Gre interface in Cluster

		# Link cluster with bridges
		for bridge in self.bridges:
			self.linkBridgeCluster(bridge, cluster)
			
		
		
		return cluster



	def linkBridgeCluster(self, bridge, cluster):
		clusterId = self.clusters.index(cluster)+1
		bridgeId = self.bridges.index(bridge)+1
		
		clusterIp = '30.0.0.%d' % clusterId
		
		bridgeIp = '20.0.0.2%d%d' % (bridgeId, clusterId)
		
		greNameBridge = 'gre%d' % clusterId
		greNameCluster = 'gre%d' % bridgeId
		
		
		
		### Create gre in cluster
		greRouter = cluster.greRouter
		
		# Create gre interface
		greRouter.cmd('ip tunnel add name '+greRouter.name+'-'+greNameCluster+' mode gre remote '+bridgeIp+' local '+clusterIp+' ttl 64 dev '+greRouter.name+'-eth0')
		greRouter.inNamespace = False
		Intf(greRouter.name+'-'+greNameCluster, greRouter)
		greRouter.inNamespace = True

		
		
		### Create gre in bridge
		# New router to support tunnel
		bridgeGre = self.mininet.addHost(bridge.name+greNameBridge, cls=LinuxRouter, ip='1.1.1.254/24' )
		
		# Link with bridge
		self.mininet.addLink(bridge, bridgeGre, intfName1=bridge.name+'-'+greNameBridge, intfName2=bridgeGre.name+'-eth0', params1={ 'ip' : '1.1.1.1/24' }, params2={ 'ip' : '1.1.1.254/24' })

		# Connect bridge to overlay
		self.mininet.addLink(self.os2, bridgeGre, intfName2=bridgeGre.name+'-eth1', params2={ 'ip' : bridgeIp+'/8' })

		# Create gre interface
		bridgeGre.cmd('ip tunnel add name '+bridgeGre.name+'-gre1'+' mode gre remote '+clusterIp+' local '+bridgeIp+' ttl 64 dev '+bridgeGre.name+'-eth1')
		bridgeGre.inNamespace = False
		Intf(bridgeGre.name+'-gre1', bridgeGre)
		bridgeGre.inNamespace = True

		## Routes
		# Default gateway
		bridgeGre.cmd('ip route add default dev '+bridgeGre.name+'-gre1')

		# To join cluster
		bridgeGre.cmd('ip route add '+clusterIp+' via 20.0.0.254')

		'''
		### Test with Linux ROUTER #### 
		# Static redirection towards last cluster
		res = None
		if bridgeId == 1:
			res = bridge.cmd('ip route add default via 1.1.1.254 dev '+bridge.name+'-gre2')
		
		if bridgeId == 2:
			res = bridge.cmd('ip route add default via 1.1.1.254 dev '+bridge.name+'-gre1')
		
		if res is None:
			res = bridge.cmd('ip route add default via 1.1.1.254 dev '+bridge.name+'-gre1')
				
		if not res:
			print('Gateway of bridge '+bridge.name+'-'+greNameBridge+' : '+clusterIp)
		'''



class VCDN( Mininet ):
	
	def __init__(self, **params):
		Mininet.__init__(self, **params)
	
		# Default controller
		defaultController = self.addController('defaultController')
		self.defaultController = defaultController
	
	
	
	def construct(self):
				
		#############################################################################
		############################### Main Function ###############################
		#############################################################################
		
		"Create VCDN network."
		
		############### CDN network construction ################
		
		# Controller for border switches
		# 	(here default controller Controller but for us RyuController)
		borderController = self.addController('borderController', CustomRyu, path='./RyuControllers/simple_switch_13.py')
		
		# Init CDN network with controller
		cdn_network = CDN(self, borderController)
		
		# Border switches in the network (return switch NOT bridge)
		#	(All connected to all clusters)
		sb1 = cdn_network.addBorderNetwork()
		sb2 = cdn_network.addBorderNetwork()
		#~ sb3 = cdn_network.addBorderNetwork()
		
		
		
		### Add cluster1 in CDN
		
		# Controller for cluster1 control the default router
		#	( Controller -> RyuController)
		cluster1Controller = self.addController('cluster1Controller', CustomRyu, path='./RyuControllers/simple_switch_13.py')
		
		# Create cluster and default router (cluster1.router)
		cluster1 = cdn_network.addCluster(cluster1Controller)
	
		# Add surrogate in cluster (auto connect to router)
		cluster1_s0 = cluster1.addSurrogate()
		
		# Create server associated to the surrogate
		http1 = cluster1_s0.addServer('http1', ip='192.168.0.10/24')
		
		
		### Add cluster2 in CDN
		
		# Controller for cluster1 control the default router
		#	( Controller -> RyuController)
		cluster2Controller = self.addController('cluster2Controller', CustomRyu, path='./RyuControllers/simple_switch_13.py')
		
		cluster2 = cdn_network.addCluster(cluster2Controller)
	
		cluster2_s0 = cluster2.addSurrogate()
		
		httpx2 = cluster2_s0.addServer('http2', ip='192.168.0.20/24')
		
		
		
		
		### Client(s) to test
		
		client = self.addHost('client1', ip='10.1.0.1/16', defaultRoute='via 10.1.0.254')
		self.addLink(client, sb1)
		
		
		client2 = self.addHost('client2', ip='10.2.0.1/16', defaultRoute='via 10.2.0.254')
		self.addLink(client2, sb2)
		client2.bashTerm()
		


		
		### Test with Linux ROUTER #### 
		# Static redirection towards last cluster
		bridges = cdn_network.bridges
		
		## Bridge 1 to cluster 2
		bridge = bridges[0]
		res = None
		res = bridge.cmd('ip route add default via 1.1.1.254 dev '+bridge.name+'-gre2')
		if not res:
			print('Gateway of bridge '+bridge.name+'-gre2 : cluster2')
		
		## Bridge 2 to cluster 1
		bridge = bridges[1]
		res = None
		res = bridge.cmd('ip route add default via 1.1.1.254 dev '+bridge.name+'-gre1')
		if not res:
			print('Gateway of bridge '+bridge.name+'-gre1'+' : cluster1')
		
		



		
		############### Network init and Tests ################
		
		### Init network
		self.start()
		
		#~ client.cmdPrint('ovs-vsctl show')
		
		# Ping test 
		# 	OK if hosts in same network (IP)
		#~ self.pingAll()
		
		# Open terminal with Client point of view
		#	Test -> "wget http://10.0.1.200" (server address)
		client.bashTerm()
		
		### Mininet cmd
		#	"exit" to exit
		CLI( self )
		
		
		################## Stop network  ################
		'''
		intf1.delete()
		'''
		
		self.stop()
	
		#############################################################################
		#############################################################################
		#############################################################################
	
	
	
	portBase = 6630
	
	def addController(self, name, cls=Controller, port=None, **kwargs):
		if not port:
			port = VCDN.portBase
			VCDN.portBase = VCDN.portBase+1
		
		#~ if isinstance(name, Controller) and not isinstance(name, RemoteController):
			#~ if name.port == 6653:
				#~ name.port = port
				
		controller = super(VCDN, self).addController(name, cls, port=port, **kwargs)
		#~ print("Contro : "+controller.__class__.__name__+" "+controller.name+" on port %d" % controller.port)
		return controller
	
	
	def addLink(self, node1, node2, **params):
		link = Mininet.addLink(self, node1, node2, **params)
		#~ print("Link   : "+link.intf1.name+' to '+link.intf2.name)
		return link
	
	def addSwitch(self, name, cls=None, **params):
		if cls is None:
			defaultController = self.defaultController
		
			class DefaultSwitch( OVSSwitch ):
				"Controler for border switches"
				def start( self, defaultControllersNotUsed ):
					# Assign controllers on the switch start
					return OVSSwitch.start( self, [defaultController] )
			
			cls = DefaultSwitch
		
		switch = Mininet.addSwitch(self, name, cls, **params)
		#~ print("Switch : "+switch.name)
		return switch
	
	def addHost(self, name, cls=CustomHost, **params):
		host = Mininet.addHost(self, name, cls, **params)
		#~ print("Host   : "+host.name)
		return host
	
	def start(self):
		
		# Disable ipv6
		for host in self.hosts + self.switches + self.controllers:
			disableIpv6(host)
		
		# Start hosts
		for host in self.hosts:
			if 'start' in inspect.getmembers(host):
				host.start()
		
		return Mininet.start(self)
	

def disableIpv6(host):
	host.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
	host.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
	host.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


'''
def test3():
	
	#~ minin = Mininet()
	minin = VCDN()
	
	r0 = minin.addHost( 'r0', cls=LinuxRouter, ip='20.0.0.254/12' )
	r1 = minin.addHost( 'r1', cls=LinuxRouter, ip='20.0.0.200/12' )

	r2 = minin.addHost( 'r2', cls=LinuxRouter, ip='40.0.0.254/12' )

	o0 = minin.addHost( 'o0', cls=LinuxRouter, ip='10.0.0.254/12' )
	o1 = minin.addHost( 'o1', cls=LinuxRouter, ip='30.0.0.254/12' )

	s1 = minin.addSwitch('s1')
	s2 = minin.addSwitch('s2')
	s3 = minin.addSwitch('s3')

	h1 = minin.addHost( 'h1', cls=CustomHost, ip='10.0.0.1/24', defaultRoute='via 10.0.0.254' )
	h2 = minin.addHost( 'h2', cls=CustomHost, ip='30.0.0.1/12', defaultRoute='via 30.0.0.254' )


	# Links

	minin.addLink( s1, o0, intfName2='o0-eth0', params2={ 'ip' : '10.0.0.254/24' } )
	minin.addLink( s2, r0, intfName2='r0-eth0', params2={ 'ip' : '20.0.0.254/12' } )
	
	minin.addLink( s3, o1, intfName2='o1-eth0', params2={ 'ip' : '30.0.0.254/12' } )
	minin.addLink( s2, r1, intfName2='r1-eth0', params2={ 'ip' : '20.0.0.200/12' } )

	minin.addLink( o0, r0, intfName1='o0-eth1', intfName2='r0-eth1', params1={ 'ip' : '1.0.0.1/12' }, params2={ 'ip' : '1.0.0.2/12' })
	minin.addLink( o1, r1, intfName1='o1-eth1', intfName2='r1-eth1', params1={ 'ip' : '1.0.0.1/12' }, params2={ 'ip' : '1.0.0.2/12' })

	minin.addLink(s1, h1)
	minin.addLink(s3, h2)

	minin.addLink( o1, r2, intfName1='o1-eth2', intfName2='r2-eth0', params1={ 'ip' : '40.0.0.100/12' }, params2={ 'ip' : '40.0.0.254/12' })
	minin.addLink( s1, r2, intfName2='r2-eth1', params2={ 'ip' : '10.0.0.200/12' } )



	# Gre

	#~ print r0.cmd('ip link add r0-gre1 type gretap local 20.0.0.254 remote 20.0.0.200 ttl 64 key 1 dev r0-eth2')
	print r0.cmd('ip tunnel add r0-gre1 mode gre remote 20.0.0.200 local 20.0.0.254 ttl 255 dev r0-eth0')
	r0.inNamespace = False
	Intf('r0-gre1', r0)
	r0.inNamespace = True
	
	
	#~ print r1.cmd('ip link add r1-gre1 type gretap local 20.0.0.200 remote 20.0.0.254 ttl 64 key 2 dev r1-eth2')
	print r1.cmd('ip tunnel add name r1-gre1 mode gre remote 20.0.0.254 local 20.0.0.200 ttl 64 dev r1-eth0')
	r1.inNamespace = False
	Intf('r1-gre1', r1)
	r1.inNamespace = True

	
	# Routes
	
	#~ r1.cmd('ip route add 10.0.0.0/24 via 20.0.0.254')
	
	print r0.cmd('ip route add 30.0.0.0/24 dev r0-gre1')
	print r1.cmd('ip route add 10.0.0.0/24 dev r1-gre1')
	
	#~ print r0.cmd('ip route add default dev r0-eth1')
	print r1.cmd('ip route add default via 1.0.0.1 dev r1-eth1')

	print r0.cmd('ip route add 20.0.0.200 via 20.0.0.254 dev r0-eth0')
	print r1.cmd('ip route add 20.0.0.254 via 20.0.0.200 dev r1-eth0')

	print o0.cmd('ip route add default via 1.0.0.2 dev o0-eth1')
	#~ print o1.cmd('ip route add default via 1.0.0.2 dev o1-eth1')

	print o1.cmd('ip route add default via 40.0.0.254 dev o1-eth2')
	
	
	minin.start()
	
	#~ s1.cmdPrint('ovs-vsctl show')
	
	#~ info( minin[ 'r0' ].cmd( 'route' ) )
	
	h1.bashTerm()
	h2.bashTerm()
	
	CLI(minin)
	minin.stop()
	exit()
'''


if __name__ == '__main__':
	setLogLevel( 'info' )  # for CLI output
	
	#~ test3()
	
	net = VCDN()
	
	try:
		net.construct()
	
	except Exception:
		net.stop()
		#~ traceback.print_exception(err)
		traceback.print_exc()
	except KeyboardInterrupt:
		net.stop()
	
	

