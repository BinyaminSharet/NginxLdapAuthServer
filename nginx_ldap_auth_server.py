#!/usr/bin/env python

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
restrict_by_group = False


def dump_cache_to_file():
    """
    Store the cache dictionary into a file
    """
    if cache_path:
        cache_f = open(cache_path, 'w')
        js = {}
        js['cache'] = cache
        js['salt'] = salt
        json.dump(js, cache_f)


def load_cache():
    """
    Load the cache dictionary from a file
    """
    global cache
    global salt
    if cache_path and os.path.isfile(cache_path):
        json_data = open(cache_path)
        cache_dict = json.load(json_data)
        cache = cache_dict['cache']
        if 'salt' in cache_dict:
            salt = cache_dict['salt']


def load_configuration(config_path):
    """
    Load configuration from file
    """
    global config
    global restrict_by_group
    json_data = open(config_path)
    config = json.load(json_data)
    restrict_by_group = config['restrict_by_group']


def check_ldap(uname, passwd, sites):
    """
    Check if user/password match and if so, return list of groups which the use
    belongs to
    """
    try:
        ldap_server = config['ldap']['server']
        l = ldap.open(ldap_server)
        l.protocol_version = ldap.VERSION3
        binddn = 'uid=%s%s' % (uname, config['ldap']['binddn_postfix'])
        bindpw = passwd
        l.simple_bind_s(binddn, bindpw)
        if restrict_by_group:
            groups = l.search_s(config['ldap']['base'], ldap.SCOPE_SUBTREE,
                                '(memberuid=%s)' % (uname), ['cn'])
            for g in groups:
                sites.extend(g[1]['cn'])
        l.unbind()
        return True
    except ldap.LDAPError, e:
        print e
        return False


def get_hashed(data):
    """
    Get hash of data + salt
    """
    return unicode(hashlib.sha512(data + unicode(salt)).hexdigest())


def is_in_cache(uname, passwd, site):
    """
    Check if matching credentials are in the cache
    """
    if uname in cache:
        ucache = cache[uname]
        if get_hashed(passwd) == ucache['passwd']:
            if not restrict_by_group:
                return True
            if site in ucache['allowed_sites']:
                return True
            else:
                #print 'requested site (%s) is not in allowed sites for user \
                #(%s)' % ( site, uname )
                #print 'allowed sites for user (%s): %s' % (uname,
                #ucache['allowed_sites'])
                pass
        else:
            #print 'password != cached passwd'
            pass
    else:
        #print 'user (%s) is not in cache' % uname
        pass
    return False


def add_to_cache(uname, passwd, sites):
    """
    Add credentials to cache
    """
    cache[uname] = {}
    cache[uname]['passwd'] = get_hashed(passwd)
    cache[uname]['allowed_sites'] = sites
    dump_cache_to_file()


def check_auth(uname, passwd, site):
    """
    High level function to check if a user authentication is OK
    """
    if is_in_cache(uname, passwd, site):
        #print 'Credentials for (%s) found in cache' % (uname)
        return True
    sites = []
    if check_ldap(uname, passwd, sites):
        #print 'LDAP authentication succeeded - storing to cache'
        add_to_cache(uname, passwd, sites)
        return is_in_cache(uname, passwd, site)
    #print 'LDAP authentication failed'
    return False


class NginxLdapAuthHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):

    """
    Handler for nginx auth_request requests
    """
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
            #print 'No authorization header, \
            #    sending WWW authentication request'
            self.send_response(401)
            self.send_header(
                'Www-Authenticate',
                'Basic realm="%s"' % (config['credentials_prompt']))
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
        s = BaseHTTPServer.HTTPServer(server_address, NginxLdapAuthHandler)
        s.serve_forever()
    except Exception as e:
        print e
        print 'Usage: %s config_file [cachefile]'
