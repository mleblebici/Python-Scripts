#!/usr/bin/env python
import argparse 
import httplib
import socket
import re

def isIP(s):
	a = s.split('.')
	if len(a) != 4:
		return False
	for x in a:
		if not x.isdigit():
			return False
		i = int(x)
		if i < 0 or i > 255:
			return False
	return True
def checkRobots_txt(target):
	conn = httplib.HTTPConnection(target)
	conn.request("GET", "/robots.txt")
	response = conn.getresponse()
	headers = response.getheaders()
	respstr = response.read()
	robots = ""
	if(response.status == 200):
		print("[*] Found robots.txt file...")
		choice = raw_input('Do you want to view the contents of robots.txt file now? [y|n]')
		robots = respstr
		if(choice == 'y'):
			print(respstr)
		if('sitemap' in respstr):
			print('[*] Found sitemap file...')
			sitemapURL = respstr[(respstr.find('Sitemap:') + 9):]
			print(sitemapURL)
			sitemapURL = sitemapURL.replace("http://", "")
			print("SitemapURL is : " + str(sitemapURL))
			sitemap = sitemapURL.split("/")
			print(sitemap[0])
			conn = httplib.HTTPConnection(sitemap[0])
			sitemapReqStr = "/"
			for i in range (1, len(sitemap)):
				sitemapReqStr += sitemap[i] + "/"
			conn.request("GET", sitemapReqStr)
			response = conn.getresponse()
			choice = raw_input('Do you want to view the contents of sitemap file now? [y|n]?')
			if(choice == 'y'):
				print(response.read())
	else:
		print("[-] robots.txt file is not public(" + str(response.status) + ": " + str(response.reason) +  ")...")
	return robots

def getOPTIONS(target):
	try:
		response = connectHTTP(target, "OPTIONS", "/")
		headers = response.getheaders()
		head = dict(headers)
		allow = head['allow']
		print("[*] Following HTTP methods are allowed on the server: " + str(allow))
	except:
		print("[-] OPTIONS method is not enabled!!!")
	return
	
def connectHTTP(target, method, reqStr):
	conn = httplib.HTTPConnection(target)
	conn.request(method, reqStr)
	response = conn.getresponse()
	if(response.status == 302 or response.status == 301):
		headers = response.getheaders()
		head = dict(headers)
		repstr = str(response.read())
		if 'location' in head:
			redirectedURL = head['location']
		else:
			startIndex = 0
			stopIndex = 0
			for i in range(0, len(respstr)):
				if(respstr[i:i+4].lower() == 'href'):
					startIndex = i+6
					break
			for i in range(startIndex, len(respstr)):
				if(respstr[i] == '"'):
					stopIndex = i
			redirectedURL = respstr[startIndex:stopIndex]
		print("\tPage is redirected to " + str(redirectedURL))
		redirectedURL = redirectedURL.replace("http://","")
		a = redirectedURL.split("/")
		reqStr = "/"
		for i in range(1, len(a)):
			reqStr += a[i] + "/"
		return connectHTTP(a[0], method, reqStr)
	return response


def sendNormalHTTPRequest(target):
	print("[*] Sending a standard HTTP GET packet...")
	response = connectHTTP(target, "GET", "/")
	respstr = str(response.read())
	headers = response.getheaders()
	headDict = dict(headers)
	if 'server' in headDict:
                print("\t[+] Server : " + str(headDict['server']))
        if 'x-powered-by' in headDict:
                print("\t[+] X-Powered-By : " + str(headDict['x-powered-by']))
        if 'x-country-code' in headDict:
                print("\t[+] X-Country-Code : " + str(headDict['x-country-code']))

	return respstr

def checkFileExtensions(target):
	response = connectHTTP(target, "GET", "/")
	respstr = str(response.read())
	extensions = {'asp':'Microsoft Active Server Pages', 'aspx':'Microsoft ASP.NET', 'jsp':'Java Server Pages', 'cfm':'Cold Fusion', 'php':'PHP language', 'd2w':'WebSphere', 'pl':'Perl language', 'py':'Python language', 'dll':'Compiled Nativa Code (C or C++)', 'nsf':'Lotus Dominol', 'ntf':'Lotus Dominol','json':'JavaScript Object Notation', 'swf':'ShockWave Flash', 'xml':'XML Document', 'cert':'Netscape', 'cgi':'Common Gateway Interface'}
	print("[*] Trying to determine underlying technologies used in the web server, based on used files...")
	for extension in extensions:
		if ('.' + str(extension)) in respstr:
			print("\t[+] " + str(extensions[extension]))

def checkCookies(target):
	cookies = {'jsessionid':'Java Platform','aspsessionid':'Microsoft ISS Server', 'asp.net_sessionid':'Microsoft ASP.NET', 'cfid':'Cold Fusion', 'cftoken':'Cold Fusion', 'phpsessid':'PHP language','phpbb3':'phpBB', 'wp-settings':'Wordpress', 'bitrix_':'1C-Bitrix', 'amp':'AMPcms', 'django':'Django CMS', 'DotNetNukeAnonymous':'DotNetNuke', 'e107_tz':'e107', 'epitrace':'EPiServer', 'episerver':'episerver', 'graffitibot':'Graffiti CMS', 'hotaru_mobile':'Hotaru CMS', 'icmsession':'ImpressCMS', 'makacsession':'Indico', 'instantcms':'instantCMS', 'cmspreferredculture':'Kentico CMS', 'fe_typo_user':'TYPO3', 'dynamicweb':'DynamicWeb', 'vivvosessionid':'VIVVO'}
	conn = httplib.HTTPConnection(target)
	conn.request("GET", "/")
	resp = conn.getresponse()
	headers = resp.getheaders()
	head = dict(headers)
	if 'set-cookie' in head:
		cookie = head['set-cookie']
		fieldss = cookie.split('=')
		for i in range(0, len(fieldss), 2):
			if(fieldss[i].lower() in cookies):
				print("[*] " + str(fieldss[i]) + " is found in cookies, server deploys " + str(cookies[fieldss[i].lower()]))
		choice = raw_input('Do you want to see the cookies?[y|n]')
		if(choice == 'y'):
			print(cookie)

def checkPhrases(text):
	print("[*] Performing known phrases check")
	phrases = ['powered by', 'built upon', 'running']
	for phrase in phrases:
		if(phrase in text.lower()):
			index = (text.lower()).find(phrase)
			for i in range(index, len(text)):
				if(text[i] == '<' and text[i+1] == "/"):
					print("\t[+] " + text[index:i-1])
					break

def getURLsWithin(target):
	response = connectHTTP(target, "GET", "/")
	link_regex = re.compile('href="(.*?)"')
	links = link_regex.findall(response.read())
	choice = raw_input('Do you want to see all URLs residing within the page?[y|n]')
	linkList = []
	if choice == 'y':
		for link in links:
			if not link in linkList:
				print("\t[+] "),
				print link
				linkList.append(link)
	return linkList

def checkDirectoriesList(linkList):
	directories = {'servlet':'Java Servlets', 'pls':'Oracle Application Server PL/SQL gateway', 'cfdocs':'ColdFusion', 'cfide':'ColdFusion', 'silverstream':'SilverStream Web Server', 'webobjects':'Apple WebObjects', 'rails':'Ruby on Rails language'}
	print("[*] Checking known directory names against links discovered...")
	for directory in directories:
		for link in linkList:
			if directory in link:
				print("\t[+] " + str(directory) + " exists in the link: " + str(link))
				print("\t[+] " + "It may indicate usage of " + str(directories[directory]))

def checkDirectoriesText(text):
	directories = {'servlet':'Java Servlets', 'pls':'Oracle Application Server PL/SQL gateway', 'cfdocs':'ColdFusion', 'cfide':'ColdFusion', 'silverstream':'SilverStream Web Server', 'webobjects':'Apple WebObjects', 'rails':'Ruby on Rails language'}
	print("[*] Checking known directory names against links discovered...")
	for directory in directories:
		if directory in text:
				print("\t[+] " + str(directory) + " exists robots.txt")
				print("\t[+] " + "It may indicate usage of " + str(directories[directory]))
			
				
def main():
	parser = argparse.ArgumentParser(prog="Web Reconnaissance Tool")
	parser.add_argument('-t', '--target', dest = "target", help = "Target to perfrom reconnaissance", required = True)
	args = parser.parse_args()
	target = args.target
	isHostname = True
	if(isIP(target)):
		isHostName = False
	
	global ip
	global hostname
	if(isHostname):
		hostname = target.replace("http://www.", "")
		hostname = target.replace("http://", "")
		ip = socket.gethostbyname(hostname)
	else:
		hostname = socket.gethostbyaddr(target)
		ip = target
	
	print("Performing fingerprinting on " + str(hostname) + "[" + str(ip) + "]...")
			
	getOPTIONS(hostname)
	httpResponseText = sendNormalHTTPRequest(hostname)
	checkPhrases(httpResponseText)
	robots = checkRobots_txt(hostname)
	checkDirectoriesText(robots)
	checkCookies(hostname)
	checkFileExtensions(hostname)
	links = getURLsWithin(hostname)
	checkDirectoriesList(links)

main()
