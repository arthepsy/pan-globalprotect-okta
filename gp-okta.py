#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
   The MIT License (MIT)
   
   Copyright (C) 2018 Andris Raugulis (moo@arthepsy.eu)
   
   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:
   
   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.
   
   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.
"""
from __future__ import print_function
import io, os, sys, re, json, base64, getpass, subprocess, shlex
from lxml import etree
import requests

if sys.version_info >= (3,):
	text_type = str
	binary_type = bytes
else:
	text_type = unicode
	binary_type = str

to_b = lambda v: v if isinstance(v, binary_type) else v.encode('utf-8')
to_u = lambda v: v if isinstance(v, text_type) else v.decode('utf-8')


def log(s):
	print('[INFO] {0}'.format(s))

def dbg(d, h, *xs):
	if not d:
		return
	print('# {0}:'.format(h))
	for x in xs:
		print(x)
	print('---')

def err(s):
	print('err: {0}'.format(s))
	sys.exit(1)

def reprr(r):
	return 'status code: {0}, text:\n{1}'.format(r.status_code, r.text)

def parse_xml(xml):
	try:
		xml = bytes(bytearray(xml, encoding='utf-8'))
		parser = etree.XMLParser(ns_clean=True, recover=True)
		return etree.fromstring(xml, parser)
	except:
		err('failed to parse xml')

def parse_html(html):
	try:
		parser = etree.HTMLParser()
		return etree.fromstring(html, parser)
	except:
		err('failed to parse html')

def parse_rjson(r):
	try:
		return r.json()
	except:
		err('failed to parse json')

def hdr_json():
	return {'Accept':'application/json', 'Content-Type': 'application/json'}

def parse_form(html):
	xform = html.find('.//form')
	url = xform.attrib.get('action', '').strip()
	data = {}
	for xinput in html.findall('.//input'):
		k = xinput.attrib.get('name', '').strip()
		v = xinput.attrib.get('value', '').strip()
		if len(k) > 0 and len(v) > 0:
			data[k] = v
	return url, data


def load_conf(cf):
	conf = {}
	keys = ['vpn_url', 'username', 'password', 'okta_url']
	with io.open(cf, 'r', encoding='utf-8') as fp:
		for rline in fp:
			line = rline.strip()
			mx = re.match('^\s*([^=\s]+)\s*=\s*(.*?)\s*(?:#\s+.*)?\s*$', line)
			if mx:
				k, v = mx.group(1).lower(), mx.group(2)
				if k.startswith('#'):
					continue
				for q in '"\'':
					if re.match('^{0}.*{0}$'.format(q), v):
						v = v[1:-1]
				conf[k] = v
	for k, v in os.environ.items():
		k = k.lower()
		if k.startswith('gp_'):
			k = k[3:]
			if len(k) == 0:
				continue
			conf[k] = v.strip()
	if len(conf.get('username', '').strip()) == 0:
		conf['username'] = raw_input('username: ').strip()
	if len(conf.get('password', '').strip()) == 0:
		conf['password'] = getpass.getpass('password: ').strip()
	for k in keys:
		if k not in conf:
			err('missing configuration key: {0}'.format(k))
		else:
			if len(conf[k].strip()) == 0:
				err('empty configuration key: {0}'.format(k))
	conf['debug'] = conf.get('debug', '').lower() in ['1', 'true']
	return conf

def paloalto_prelogin(conf, s):
	log('prelogin request')
	r = s.get('{0}/global-protect/prelogin.esp'.format(conf.get('vpn_url')))
	if r.status_code != 200:
		err('prelogin request failed. {0}'.format(reprr(r)))
	dbg(conf.get('debug'), 'prelogin.response', reprr(r))
	x = parse_xml(r.text)
	saml_req = x.find('.//saml-request')
	if saml_req is None:
		err('did not find saml request')
	if len(saml_req.text.strip()) == 0:
		err('empty saml request')
	try:
		saml_raw = base64.b64decode(saml_req.text)
	except:
		err('failed to decode saml request')
	dbg(conf.get('debug'), 'prelogin.decoded', saml_raw)
	saml_xml = parse_html(saml_raw)
	return saml_xml

def okta_saml(conf, s, saml_xml):
	log('okta saml request')
	url, data = parse_form(saml_xml)
	r = s.post(url, data=data)
	if r.status_code != 200:
		err('okta saml request failed. {0}'.format(reprr(r)))
	dbg(conf.get('debug'), 'saml.response', reprr(r))
	c = r.text
	rx_base_url = re.search(r'var\s*baseUrl\s*=\s*\'([^\']+)\'', c)
	rx_from_uri = re.search(r'var\s*fromUri\s*=\s*\'([^\']+)\'', c)
	if rx_base_url is None:
		err('did not find baseUrl in response')
	if rx_from_uri is None:
		err('did not find fromUri in response')
	base_url = to_b(rx_base_url.group(1)).decode('unicode_escape').strip()
	from_uri = to_b(rx_from_uri.group(1)).decode('unicode_escape').strip()
	if from_uri.startswith('http'):
		redirect_url = from_uri
	else:
		redirect_url = base_url + from_uri
	return redirect_url

def okta_auth(conf, s):
	log('okta auth request')
	url = '{0}/api/v1/authn'.format(conf.get('okta_url'))
	data = {
		'username': conf.get('username'), 
		'password': conf.get('password'), 
		'options': {
			'warnBeforePasswordExpired':True,
			'multiOptionalFactorEnroll':True
		}
	}
	r = s.post(url, headers=hdr_json(), data=json.dumps(data))
	if r.status_code != 200:
		err('okta auth request failed. {0}'.format(reprr(r)))
	dbg(conf.get('debug'), 'auth.response', reprr(r))
	j = parse_rjson(r)
	status = j.get('status', '').strip()
	dbg(conf.get('debug'), 'status', status)
	if status.lower() == 'success':
		session_token = j.get('sessionToken', '').strip()
	elif status.lower() == 'mfa_required':
		session_token = okta_mfa(conf, s, j)
	else:
		print(j)
		err('unknown status')
	if len(session_token) == 0:
		err('empty session token')
	return session_token

def okta_mfa(conf, s, j):
	state_token = j.get('stateToken', '').strip()
	if len(state_token) == 0:
		err('empty state token')
	factors_json = j.get('_embedded', {}).get('factors', [])
	if len(factors_json) == 0:
		err('no factors found')
	factors = []
	for factor in factors_json:
		factor_id = factor.get('id', '').strip()
		factor_type = factor.get('factorType', '').strip().lower()
		provider = factor.get('provider', '').strip().lower()
		factor_url = factor.get('_links', {}).get('verify', {}).get('href')
		if len(factor_type) == 0 or len(provider) == 0 or len(factor_url) == 0:
			continue
		factors.append({
			'id': factor_id,
			'type': factor_type,
			'provider': provider,
			'url': factor_url})
	dbg(conf.get('debug'), 'factors', factors)
	if len(factors) == 0:
		err('no factors found')
	totp_factors = [x for x in factors if x.get('type') == 'token:software:totp']
	dbg(conf.get('debug'), 'topt_factors', totp_factors)
	if len(totp_factors) == 0:
		err('no totp factors found')
	return okta_mfa_totp(conf, s, totp_factors, state_token)

def okta_mfa_totp(conf, s, factors, state_token):
	for factor in factors:
		provider = factor.get('provider', '')
		secret = conf.get('totp.{0}'.format(provider))
		if secret is None:
			order = 2
		elif len(secret) == 0:
			order = 1
		else:
			order = 0
		factor['order'] = order
	for factor in sorted(factors, key=lambda x: x.get('order', 0)):
		provider = factor.get('provider', '')
		secret = conf.get('totp.{0}'.format(provider), '') or ''
		code = None
		if len(secret) == 0:
			code = raw_input('{0} TOTP: '.format(provider)).strip()
		else:
			import pyotp
			totp = pyotp.TOTP(secret)
			code = totp.now()
		code = code or ''
		if len(code) == 0:
			continue
		data = {
			'factorId': factor.get('id'),
			'stateToken': state_token,
			'passCode': code
		}
		log('mfa {0} totp request'.format(provider))
		r = s.post(factor.get('url'), headers=hdr_json(), data=json.dumps(data))
		if r.status_code != 200:
			err('okta mfa request failed. {0}'.format(reprr(r)))
		dbg(conf.get('debug'), 'mfa.response', r.status_code, r.text)
		j = parse_rjson(r)
		return j.get('sessionToken', '').strip()
	err('no totp was processed')

def okta_redirect(conf, s, session_token, redirect_url):
	data = {
		'checkAccountSetupComplete': 'true',
		'report': 'true',
		'token': session_token,
		'redirectUrl': redirect_url
	}
	url = '{0}/login/sessionCookieRedirect'.format(conf.get('okta_url'))
	log('okta redirect request')
	r = s.post(url, data=data)
	if r.status_code != 200:
		err('redirect request failed. {0}'.format(reprr(r)))
	dbg(conf.get('debug'), 'redirect.response', r.status_code, r.text)
	xhtml = parse_html(r.text)
	
	url, data = parse_form(xhtml)
	log('okta redirect form request')
	r = s.post(url, data=data)
	if r.status_code != 200:
		err('redirect form request failed. {0}'.format(reprr(r)))
	dbg(conf.get('debug'), 'form.response', r.status_code, r.text)
	saml_username = r.headers.get('saml-username', '').strip()
	if len(saml_username) == 0:
		err('saml-username empty')
	saml_auth_status = r.headers.get('saml-auth-status', '').strip()
	saml_slo = r.headers.get('saml-slo', '').strip()
	prelogin_cookie = r.headers.get('prelogin-cookie', '').strip()
	if len(prelogin_cookie) == 0:
		err('prelogin-cookie empty')
	return saml_username, prelogin_cookie

def paloalto_getconfig(conf, s, saml_username, prelogin_cookie):
	log('getconfig request')
	url = '{0}/global-protect/getconfig.esp'.format(conf.get('vpn_url'))
	data = {
		'user': saml_username, 
		'passwd': '',
		'inputStr': '',
		'clientVer': '4100',
		'clientos': 'Windows',
		'clientgpversion': '4.1.0.98',
		'computer': 'DESKTOP',
		'os-version': 'Microsoft Windows 10 Pro, 64-bit',
		# 'host-id': '00:11:22:33:44:55'
		'prelogin-cookie': prelogin_cookie,
		'ipv6-support': 'yes'
	}
	r = s.post(url, data=data)
	if r.status_code != 200:
		err('getconfig request failed. {0}'.format(reprr(r)))
	dbg(conf.get('debug'), 'getconfig.response', reprr(r))
	x = parse_xml(r.text)
	xtmp = x.find('.//portal-userauthcookie')
	if xtmp is None:
		err('did not find portal-userauthcookie')
	portal_userauthcookie = xtmp.text
	if len(portal_userauthcookie) == 0:
		err('empty portal_userauthcookie')
	return portal_userauthcookie


def main():
	if len(sys.argv) < 2:
		print('usage: {0} <conf>'.format(sys.argv[0]))
		sys.exit(1)
	conf = load_conf(sys.argv[1])
	
	s = requests.Session()
	s.headers['User-Agent'] = 'PAN GlobalProtect'
	saml_xml = paloalto_prelogin(conf, s)
	redirect_url = okta_saml(conf, s, saml_xml)
	token = okta_auth(conf, s)
	log('sessionToken: {0}'.format(token))
	saml_username, prelogin_cookie = okta_redirect(conf, s, token, redirect_url)
	log('saml-username: {0}'.format(saml_username))
	log('prelogin-cookie: {0}'.format(prelogin_cookie))
	userauthcookie = paloalto_getconfig(conf, s, saml_username, prelogin_cookie)
	log('portal-userauthcookie: {0}'.format(userauthcookie))
	
	cmd = conf.get('openconnect_cmd') or 'openconnect'
	cmd += ' --protocol=gp -u "{0}"'
	cmd += ' --usergroup portal:portal-userauthcookie'
	cmd += ' --passwd-on-stdin ' + conf.get('openconnect_args') + ' "{1}"'
	cmd = cmd.format(saml_username, conf.get('vpn_url'))
	gw = (conf.get('gateway') or '').strip()
	nlbug = '\\n' if conf.get('bug.nl', '').lower() in ['1', 'true'] else ''
	if len(gw) > 0:
		pcmd = 'printf "' + nlbug + '{0}\\n{1}"'.format(userauthcookie, gw)
	else:
		pcmd = 'printf "' + nlbug + '{0}"'.format(userauthcookie)
	print()
	if conf.get('execute', '').lower() in ['1', 'true']:
		cmd = shlex.split(cmd)
		cmd = [os.path.expandvars(os.path.expanduser(x)) for x in cmd]
		pp = subprocess.Popen(shlex.split(pcmd), stdout=subprocess.PIPE)
		cp = subprocess.Popen(cmd, stdin=pp.stdout, stdout=subprocess.PIPE)
		pp.stdout.close()
		cp.communicate()
	else:
		print('{0} | {1}'.format(pcmd, cmd))


if __name__ == '__main__':
	main()
