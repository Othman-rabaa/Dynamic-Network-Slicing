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
import os

def topology():

    net = Mininet( topo=None,
                   build=False,
                   ipBase='10.0.0.0/8',
                   link=TCLink,)

    info( '*** Adding controller\n' )
    c0=net.addController(name='c1',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6633)

    info( '*** Add switches\n')
    s5 = net.addSwitch('s5', cls=OVSKernelSwitch)
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch)
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch)
    s6 = net.addSwitch('s6', cls=OVSKernelSwitch)
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch)

    info( '*** Add hosts\n')
    h2 = net.addHost('h2', cls=Host, ip='10.0.0.2', defaultRoute=None)
    h3 = net.addHost('h3', cls=Host, ip='10.0.0.3', defaultRoute=None)
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.1', defaultRoute=None)
    h4 = net.addHost('h4', cls=Host, ip='10.0.0.4', defaultRoute=None)
    h5 = net.addHost('h5', cls=Host, ip='10.0.0.5', defaultRoute=None)
    h6 = net.addHost('h6', cls=Host, ip='10.0.0.6', defaultRoute=None)


    info( '*** Add links\n')
    net.addLink(h1, s1,delay='5ms', bw=100)
    net.addLink(h2, s1,delay='5ms', bw=100)
    net.addLink(h3, s1,delay='5ms', bw=100)
    net.addLink(h4, s2,delay='5ms', bw=100)
    net.addLink(h5, s2,delay='5ms', bw=100)
    net.addLink(h6, s2,delay='5ms', bw=100)


    net.addLink(s2, s4,delay='10ms', bw=40)
    net.addLink(s2, s6,delay='50ms', bw=100)
    net.addLink(s1, s3,delay='10ms', bw=100)
    net.addLink(s1, s5,delay='70ms', bw=100)
    net.addLink(s5, s4,delay='100ms', bw=100)
    net.addLink(s5, s6,delay='80ms', bw=100)
    net.addLink(s3, s4,delay='10ms', bw=70)
    net.addLink(s3, s6,delay='10ms', bw=100)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s5').start([c0])
    net.get('s3').start([c0])
    net.get('s4').start([c0])
    net.get('s6').start([c0])
    net.get('s1').start([c0])
    net.get('s2').start([c0])

    info( '*** Post configure switches and hosts\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    topology()