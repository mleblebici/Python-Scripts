#!/usr/bin/env python
from httplib import HTTPConnection
import httplib
import requests
from difflib import SequenceMatcher
import tabulate
import argparse
import time

class myHTTPConnection(HTTPConnection):
	_http_vsn_str = '9.9'

# [TEST #1] send legitimate HTTP GET request for an existing resource
def GET_Existing(target):
	try:
		req = requests.get(target)
		headers = req.headers
	except:
		print('Could not send the request, test aborted!!!')
		return {}, '0', 'error'
	return dict(headers), req.status_code, req.reason

# [TEST #2] send very long HTTP GET request
def GET_Long_Request(target):
	payload = 'abcdefgh'*516
	try:
		req = requests.get(target, data = payload)
		headers = req.headers
	except:
		print('Could not send the request, test aborted!!!')
		return {}, '0', 'error'
	return dict(headers), req.status_code, req.reason

# [TEST #3] send legitimate HTTP GET request for an non-existing resource
def GET_NonExisting(target):
	requestPath = target + '/nonexistingfileasdasdadwerwertxt'
	try:
		req = requests.get(requestPath)
		headers = req.headers
	except:
		print('Could not send the request, test aborted!!!')
		return {}, '0', 'error'
	return dict(headers), req.status_code, req.reason

# [TEST #4] send HTTP HEAD request for an existing resource
def HEAD_Existing(target):
	try:
		req = requests.head(target)
		headers = req.headers
	except:
		print('Could not send the request, test aborted!!!')
		return {}, '0', 'error'
	return dict(headers), req.status_code, req.reason

# [TEST #5] send OPTIONS request to determine allowed methods
def OPTIONS_Common(target):
	try:
		req = requests.options(target)
		headers = req.headers
	except:
		print('The connection was reset by the server.')
		return {}, '0', 'error'
	return dict(headers), req.status_code, req.reason

# [TEST #6] send DELETE request
def DELETE_Existing(target):
	try:
		req = requests.delete(target)
		headers = req.headers
	except:
		print('The connection was reset by the server.')
		return {}, '0', 'error'
	return dict(headers), req.status_code, req.reason

# [TEST #7] send non-existing HTTP method FOO
def TEST_Method(target):
	target = target.replace('http://', '')
	target = target.replace('www.', '')
	try:
		conn = httplib.HTTPConnection(target)
	except:
		print('Could not send the request, test aborted!!!')
		return {}, '0', 'error'
	try:
		conn.request('LBC', '/')
		resp = conn.getresponse()
	except :
		print('Could not get any answer, connection was closed by the server.')
		return {}, '0', 'error'
	headers = resp.getheaders()
	return dict(headers), resp.status, resp.reason

# [TEST #8a] send HTTP GET request with an attack pattern XSS
def Attack_Request(target):
	requestPath = str(target) + '/forum.php?user=<script>alert(document.cookie);</script>'
	try:
		req = requests.get(requestPath, verify=False, timeout=5)
	except requests.exceptions.ReadTimeout:
		print('Request timed out! That may be because of an IPS or FW')
		return {}, '0', 'error'
	headers = req.headers
	return dict(headers), req.status_code, req.reason

# [TEST #8b] send HTTP GET request with an attack pattern path traversal
def AttackRequest2(target):
	requestPath = str(target) + '/../../../../../etc/passwd'
	try:
		req = requests.get(requestPath)
		headers = req.headers
	except:
		print('Could not send the request, test aborted')
		return {}, '0', 'error'
	return dict(headers), req.status_code, req.reason

# [TEST #9] send non-existing HTTP version
def GET_Wrong_Protocol(target):
	target = target.replace('http://', '')
	target = target.replace('www.', '')
	try:
		connection = myHTTPConnection(target)
	except:
		print('Could not send the request, test aborted!!!')
		return {}, '0', 'error'
	try:
		connection.request('GET', '/')
		response = connection.getresponse()
		headers = response.getheaders()
	except:
		print('Could not get any answer, connection was closed by the server.')
		return {}, '0', 'error'
	return dict(headers), response.status, response.reason

def printHTTPResponse(headers):
	head = dict(headers)
	data = sorted([(v,k) for v,k in head.items()])
	print tabulate.tabulate(data)
	
def generateFeatureVector(headers, status, reason):
	featureVector = []
	# accept-ranges
	try:
		featureVector.append(str(headers['Accept-Ranges']))
	except KeyError:
		featureVector.append('missing')

	# server
	try:
		headers['Server'].replace('Microsoft IIS', 'IIS')
		headers['Server'].replace('IIS', 'Microsoft IIS')
		featureVector.append(str(headers['Server']))

	except KeyError:
		featureVector.append('missing')
	
	# cache-control
	try:
		featureVector.append(str(headers['Cache-Control']))
	except KeyError:
		featureVector.append('missing')
	
	# connection
	try:
		featureVector.append(str(headers['Connection']))
	except KeyError:
		featureVector.append('missing')

	# content-type
	try:
		featureVector.append(str(headers['Content-Type']))
	except KeyError:
		featureVector.append('missing')

	# etag
	try:
		featureVector.append(str(headers['ETag']))
	except KeyError:
		featureVector.append('missing')

	# header-capital-after-dash
	gotit = False
	for header in headers:
		if('-' in headers[header]):
			if((headers[header])[((headers[header]).index('-') + 1)] != (headers[header])[((headers[header]).index('-') + 1)].lower()): 
				featureVector.append('1')
				gotit = True
				break
			else:
				featureVector.append('0')
				gotit = True
				break
	if(not gotit):
		featureVector.append('missing')

	# header-order
	order = ""
	for header in headers:
		order += (str(header) + ',')
	featureVector.append(order)
	
	# www-authenticate 
	try:
		featureVector.append(str((headers['WWW-Authenticate'])[headers['WWW-Authenticate'].index('="') + 2: -1]))
	except KeyError:
		featureVector.append('missing')

	# options allow
	try:
		featureVector.append(str(headers['Allow']))
	except KeyError:
		featureVector.append('missing')

	# pragma
	try:
		featureVector.append(str(headers['Pragma']))
	except KeyError:
		featureVector.append('missing')
	
	# status code and reason
	featureVector.append(str(status))
	featureVector.append(str(reason))

	# x-powered-by
	try:	
		featureVector.append(str(headers['X-Powered-By']))
	except KeyError:
		featureVector.append('missing')

	
	return featureVector	

def compareStrings(a, b):
	return SequenceMatcher(None, a, b).ratio()

def generateTxtFiles(testNumber):
	dirName = 'database/test' + str(testNumber) + '/'
	txtFiles = []
	for i in range(0, 14):
		txtFiles.append(dirName + 'fv' + str(i + 1) + '.txt')
	return txtFiles
	
def testSum(fv, serverSums, testNumber):
	txtFiles = generateTxtFiles(testNumber)
	coefficients = [4, 20, 6, 6, 5, 8, 3, 20, 8, 8, 7, 3, 3, 20]
	coefficients = [x*100 for x in coefficients]
	for i in range(0, len(fv)):
		# read feature vectors database
		f = open(txtFiles[i], 'r')
		lines = f.readlines()
		f.close()

		for line in lines:
			a = line.split(';')
			a[1] = a[1].replace('\n', '')
			a[1] = a[1].replace('\r', '')
			if(compareStrings(fv[i], a[1]) > 0.80):
				serverSums[a[0]] = serverSums[a[0]] + coefficients[i]
	return serverSums

def initializeServerSums():
	# initializing the serverSums list
	serverSums = {}
	f = open('serverlist.txt', 'r')
	ff = f.readlines()
	f.close()
	
	for line in ff:
		serverSums[line.replace('\n', '')] = 0
	
	return serverSums

def performTests(target, testNumbers):
	# initialize the serverSums list
	serverSums = initializeServerSums()
	testList = [GET_Existing, GET_Long_Request, GET_NonExisting, HEAD_Existing, OPTIONS_Common, DELETE_Existing, TEST_Method, Attack_Request, GET_Wrong_Protocol]
	
	for test in testNumbers:
		print('[*] Performing test ' + testList[test - 1].__name__)
		headers, status, reason = testList[test - 1](target)
		if(status == '0' or reason == 'error' or headers == {}):
			print('[-] Test ' + testList[test - 1].__name__ + ' failed and it will not be used during decision making.')
		else: 
			print('Headers of the associated HTTP response')
			printHTTPResponse(headers)
			fv = generateFeatureVector(headers, status, reason)
			serverSums = testSum(fv, serverSums, test)
		time.sleep(1)
	return serverSums

def determineMaxElement(dictionary):
	return max(dictionary, key=dictionary.get)

def showAllTests():
	table = [[1, 'GET existing'], [2, 'GET long request'], [3, 'GET non-existing'], [4, 'HEAD Existing'], [5, 'OPTIONS Common'], [6, 'DELETE Existing'], [7, 'TEST method'], [8, 'Attack Request'], [9, 'GET wrong protocol']]
	print tabulate.tabulate(table)


def main():
	parser = argparse.ArgumentParser(description='Web Server Fingerprinter')
	parser.add_argument('-t', '--target', dest = 'target', help='Full URL of the web site', required=True)
	parser.add_argument('--test', '-n', dest='testNumbers', type=int, nargs='+', help='List of tests to be performed')
	parser.add_argument('-l', '--list', action='store_true', dest='listTests', help='Lists all tests available')
	args = parser.parse_args()

	target = args.target

	serverSums = {}
	if(args.listTests):
		showAllTests()
		exit()
	else:
		if(args.testNumbers == None):
			testNumbers = [1, 2, 3, 4, 5, 6, 7, 8, 9]
		else:
			testNumbers = args.testNumbers	
		serverSums = performTests(target, testNumbers)	
	print('Based on the tests, the five most likely estimates are: ')
	table = []
	for i in range(0, 5):
		table.append([(i+1), determineMaxElement(serverSums)])
		del serverSums[determineMaxElement(serverSums)]
	print tabulate.tabulate(table)		
main()
