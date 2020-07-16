#!/usr/bin/python3


import os
import sys
import nmap3
import threading


interface = sys.argv[1]
gateway_ip = sys.argv[2]

mac = None

victims = []
threads = []


class attackThread(threading.Thread):
	def __init__(self, gateway, victim):
		threading.Thread.__init__(self)
		self.victim = victim
		self.gateway = gateway

		# Other
		self.arp = b'\x08\x06'
		self.protocol = b'\x00\x01\x08\x00\x06\x04\x00\x02'

	def run(self):
		#


def attack(ips):
	for ip in ips:
		threads.append(attackThread(gateway_ip, ip))

	for th in threads:
		th.start()


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


def main():
	if interface in netifaces.interfaces():
		mac = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]["addr"]

	else:
		print(f"Interface {interface} not found")
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
		scanner("192.168.1.0/24")

	print("Running the attack..")
	attack(victims)


if __name__== "__main__":
	try:
		main()
	except KeyboardInterrupt:
		print("Attack was stopped.")




