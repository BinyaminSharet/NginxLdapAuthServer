#!/usr/bin/env python

import threading
import webbrowser
import BaseHTTPServer
import SimpleHTTPServer
import ldap
import hashlib
import uuid
import json
import sys
import os

config = {}
cache = {}

salt = uuid.uuid4().hex

cache_path = None

def store_cache():
	if cache_path:
		cache_f = open(cache_path,'w')
		js = {}
		js['cache'] = cache
		js['salt'] = salt
		json.dump(js, cache_f)


def load_cache():
	global cache
	global salt
	if cache_path and os.path.isfile(cache_path):
		json_data = open(cache_path)
		cache_dict = json.load(json_data)
		cache = cache_dict['cache']
		if 'salt' in cache_dict:
			salt = cache_dict['salt']


def load_configuration(config_path):
	global config
	json_data = open(config_path)
	config = json.load(json_data)


def check_ldap(uname, passwd, sites):
	try:
		ldap_server = config['ldap']['server']
		l = ldap.open(ldap_server)
		l.protocol_version = ldap.VERSION3 # should be 3 or 2?
		binddn = 'uid=%s%s' % ( uname, config['ldap']['binddn_postfix'] )
		bindpw = passwd
		l.simple_bind_s(binddn, bindpw)
		groups = l.search_s(config['ldap']['base'], ldap.SCOPE_SUBTREE, '(memberuid=%s)' % (uname), ['cn'])
		for g in groups:
			sites.extend(g[1]['cn'])
		l.unbind()
		return True
	except ldap.LDAPError, e:
		print e
		return False


def get_hashed(data):
	return unicode(hashlib.sha512(data + unicode(salt)).hexdigest())


def is_in_cache(uname, passwd, site):
	if uname in cache:
		if get_hashed(passwd) == cache[uname]['passwd']:
			if site in cache[uname]['allowed_sites']:
				return True
			else:
				#print 'requested site (%s) is not in allowed sites for user (%s)' % ( site, uname )
				#print 'allowed sites for user (%s): %s' % (uname, cache[uname]['allowed_sites'])
				pass
		else:
			#print 'password != cached passwd'
			pass
	else:
		#print 'user (%s) is not in cache' % uname
		pass
	return False


def store_to_cache(uname, passwd, sites):
	cache[uname] = {}
	cache[uname]['passwd'] = get_hashed(passwd)
	cache[uname]['allowed_sites'] = sites
	store_cache()


def check_auth(uname, passwd, site):
	if is_in_cache(uname, passwd, site):
		#print 'Credentials for (%s) found in cache' % (uname) 
		return True
	sites = []
	if check_ldap(uname, passwd, sites):
		#print 'LDAP authentication succeeded - storing to cache'
		store_to_cache(uname, passwd, sites)
		return is_in_cache(uname, passwd, site)
	#print 'LDAP authentication failed'
	return False


class NginxLdapAuthHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):

	def do_GET(self):
		auth = self.headers.getheader('Authorization')
		site = self.headers.getheader('Request-Site')
		#print 'Request-site: %s' % (site)
		
		#
		# has authorization header
		#
		if auth:
			uname_passwd = auth.strip().split()[1].decode('base64')
			#print 'Has authorization header'
			uname, x, passwd = unicode(uname_passwd).partition(':')
			if check_auth(unicode(uname), unicode(passwd), unicode(site)):
				self.send_response(200)
			else:
				self.send_response(401)
			self.end_headers()

		#
		# no authorization header - prompt for username and password
		#
		else:
			#print 'No authorization header, sending WWW authentication request'
			self.send_response(401)
			self.send_header('Www-Authenticate', 'Basic realm="%s"' % (config['credentials_prompt']))
			self.end_headers()


if __name__ == '__main__':
	try:
		print '--- Nginx LDAP Authentication server ---'
		if len(sys.argv) == 1:
			raise 'Not enough arguments'
		if len(sys.argv) > 1:
			load_configuration(sys.argv[1])
		if len(sys.argv) > 2:
			cache_path = sys.argv[2]
		load_cache()
		server_address = (config['server_ip'], config['server_port'])
		server = BaseHTTPServer.HTTPServer(server_address, NginxLdapAuthHandler)
		server.serve_forever()
	except Exception as e:
		print e
		print 'Usage: %s config_file [cachefile]'
