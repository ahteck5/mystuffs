import sys, socket, struct, requests
import urllib3
import urllib
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from collections import OrderedDict
from urllib import urlencode

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

host = "10.202.202.200"

def nessus_login(host):
	
	target = "https://%s/session" % host

	http_proxy  = "http://%s:8080" % host
	proxyDict = { 
		"https"  : http_proxy
	}
	
	d = {
		"username" : "linuxvascanner",
		"password": "gtrt1qaz@WSX",
		}

	headers = {
		'Accept' : 'application/json', 
		'Content-Type' : 'application/json'

		}


	s = requests.Session()
	r = s.post(target, data=json.dumps(d), proxies=proxyDict, headers=headers, verify=False)
	res = r.text

	if "\"token\":" in res:
		json_data = json.loads(res)
		print json_data['token']
		return json_data['token']

	return False

def import_scantemplate(host, token):

	target = "https://%s/policies/import" % host
	
	http_proxy  = "http://127.0.0.1:8080"
	proxyDict = { 
		"https"  : http_proxy
	}

	d = {
		"file":"test3.xml",
	
	}
	
	s = requests.Session()
	print "cookie " + token
	logintoken = "token="+token 
	s.cookies['X-Cookie'] = logintoken

	res = ""
	try:
		r = s.post(target, data=json.dumps(d), proxies=proxyDict, verify=False)
		res = r.text
	except Exception as e:
		print str(e)
	
	if "name" in res:
		return True

	return False
	

def main():
	token = nessus_login(host)
	
	if not False:
		print "(+) Login success!"
		
		if add_scantemplate(host, token):
			print "(+) Add Scan Template success!"
		else:
			print "(-) Add Scan Template failed!"			
	else:
		print "(-) Login failed!"

if __name__ == "__main__":
	main()


