#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
   The MIT License (MIT)

   Copyright (C) 2018-2020 Andris Raugulis (moo@arthepsy.eu)
   Copyright (C) 2018 Nick Lanham (nick@afternight.org)
   Copyright (C) 2019 Aaron Lindsay (aclindsa@gmail.com)
   Copyright (C) 2019 Taylor Dean (taylor@makeshift.dev)
   Copyright (C) 2020 Max Lanin (mlanin@evolutiongaming.com)
   Copyright (C) 2019-2020 Tino Lange (coldcoff@yahoo.com)

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
from __future__ import print_function, unicode_literals
import io, os, sys, time, re, json, base64, getpass, subprocess, shlex, signal, tempfile, traceback

from lxml import etree
import requests
import argparse

if sys.version_info >= (3,):
	from urllib.parse import urlparse, urljoin
	text_type = str
	binary_type = bytes
else:
	from urlparse import urlparse, urljoin
	text_type = unicode
	binary_type = str
	input = raw_input

# Optional: fido2 support (webauthn via Yubikey)
have_fido = False
try:
	from fido2.utils import websafe_decode, websafe_encode
	from fido2.hid import CtapHidDevice
	from fido2.client import Fido2Client
	have_fido = True
except ImportError:
	pass

# Optional: pyotp support
have_pyotp = False
try:
	import pyotp
	have_pyotp = True
except ImportError:
	pass

# Optional: gnupg support
have_gnupg = False
try:
	import gnupg
	have_gnupg = True
except ImportError:
	pass

to_b = lambda v: v if isinstance(v, binary_type) else v.encode('utf-8')
to_u = lambda v: v if isinstance(v, text_type) else v.decode('utf-8')

quiet = False

def log(s):
	if not quiet:
		print('[INFO] {0}'.format(s))

def warn(s):
	if not quiet:
		print('[WARN] {0}'.format(s))

def dbg(d, h, *xs):
	if quiet:
		return
	if not d:
		return
	for x in xs:
		if not isinstance(x, dict) and not isinstance(x, list):
			for line in x.split('\n'):
				print('[DEBUG] {0}: {1}'.format(h, line))
		else:
			print('[DEBUG] {0}: {1}'.format(h, x))

def dbg_form(conf, name, data):
	if not conf.get('debug'):
		return
	for k in data:
		dbg(True, name, '{0}: {1}'.format(k, data[k]))
		if k in ['SAMLRequest', 'SAMLResponse']:
			try:
				saml_raw = base64.b64decode(data[k])
				dbg(True, name, '{0}.decoded: {1}'.format(k,  saml_raw))
			except:
				pass


def err(s):
	print('[ERROR] {0}'.format(s), file=sys.stderr)
	sys.exit(1)

def parse_xml(xml):
	try:
		xml = bytes(bytearray(xml, encoding='utf-8'))
		parser = etree.XMLParser(ns_clean=True, recover=True)
		return etree.fromstring(xml, parser)
	except Exception as e:
		err('failed to parse xml: ' + e)

def parse_html(html):
	try:
		parser = etree.HTMLParser()
		return etree.fromstring(html, parser)
	except Exception as e:
		err('failed to parse html: ' + e)

def parse_rjson(r):
	try:
		return r.json()
	except Exception as e:
		err('failed to parse json: ' + e)

def parse_form(html, current_url = None):
	xform = html.find('.//form')
	url = xform.attrib.get('action', '').strip()
	if not url.startswith('http') and current_url:
		url = urljoin(current_url, url)
	data = {}
	for xinput in html.findall('.//input'):
		k = xinput.attrib.get('name', '').strip()
		v = xinput.attrib.get('value', '').strip()
		if len(k) > 0 and len(v) > 0:
			data[k] = v
	return url, data

def load_conf(cf):
	log('load conf')
	conf = {}
	keys = ['vpn_url', 'username', 'password', 'okta_url']
	if isinstance(cf, binary_type):
		cf = cf.decode('utf-8')
	line_nr = 0
	for rline in cf.split('\n'):
		line_nr += 1
		line = rline.strip()
		mx = re.match(r'^\s*([^=\s]+)\s*=\s*(.*?)\s*(?:#\s+.*)?\s*$', line)
		if mx:
			k, v = mx.group(1).lower(), mx.group(2)
			if k.startswith('#'):
				continue
			for q in '"\'':
				if re.match(r'^{0}.*{0}$'.format(q), v):
					v = v[1:-1]
			conf[k] = v
			conf['{0}.line'.format(k)] = line_nr
	for k, v in os.environ.items():
		k = k.lower()
		if k.startswith('gp_'):
			k = k[3:]
			if len(k) == 0:
				continue
			conf[k] = v.strip()
	if len(conf.get('username', '').strip()) == 0:
		conf['username'] = input('username: ').strip()
	if len(conf.get('password', '').strip()) == 0:
		conf['password'] = getpass.getpass('password: ').strip()
	if len(conf.get('openconnect_certs', '').strip()) == 0:
		conf['openconnect_certs'] = tempfile.NamedTemporaryFile()
		log('will collect openconnect_certs in temporary file: {0} and verify against them'.format(conf['openconnect_certs'].name))
	else:
		conf['openconnect_certs'] = open(conf['openconnect_certs'], 'wb')
	if len(conf.get('vpn_url_cert', '').strip()) != 0:
		if not os.path.exists(conf.get('vpn_url_cert')):
			err('configured vpn_url_cert file does not exist')
		conf['openconnect_certs'].write(open(conf.get('vpn_url_cert'), 'rb').read()) # copy it
	if len(conf.get('okta_url_cert', '').strip()) != 0:
		if not os.path.exists(conf.get('okta_url_cert')):
			err('configured okta_url_cert file does not exist')
		conf['openconnect_certs'].write(open(conf.get('okta_url_cert'), 'rb').read()) # copy it
	if len(conf.get('client_cert', '').strip()) != 0:
		if not os.path.exists(conf.get('client_cert')):
				err('configured client_cert file does not exist')
	for k in keys:
		if k not in conf:
			err('missing configuration key: {0}'.format(k))
		else:
			if len(conf[k].strip()) == 0:
				err('empty configuration key: {0}'.format(k))
	conf['debug'] = conf.get('debug', '').lower() in ['1', 'true']
	conf['openconnect_certs'].flush()
	return conf

def mfa_priority(conf, ftype, fprovider):
	if ftype == 'token:software:totp' or (ftype, fprovider) == ('token', 'symantec'):
		ftype = 'totp'
	if ftype not in ['totp', 'sms', 'push', 'webauthn']:
		return 0
	mfa_order = conf.get('mfa_order', '')
	if ftype in mfa_order:
		priority = (10 - mfa_order.index(ftype)) * 100
	else:
		priority = 0
	value = conf.get('{0}.{1}'.format(ftype, fprovider))
	if ftype in ('sms', 'webauthn'):
		if not (value or '').lower() in ['1', 'true']:
			value = None
	line_nr = conf.get('{0}.{1}.line'.format(ftype, fprovider), 0)
	if value is None:
		priority += 0
	elif len(value) == 0:
		priority += (128 - line_nr)
	else:
		priority += (512 - line_nr)
	return priority

def get_state_token(conf, c, current_url = None):
	rx_state_token = re.search(r'var\s*stateToken\s*=\s*\'([^\']+)\'', c)
	if not rx_state_token:
		dbg(conf.get('debug'), 'not found', 'stateToken')
		return None
	state_token = to_b(rx_state_token.group(1)).decode('unicode_escape').strip()
	return state_token

def get_redirect_url(conf, c, current_url = None):
	rx_base_url = re.search(r'var\s*baseUrl\s*=\s*\'([^\']+)\'', c)
	rx_from_uri = re.search(r'var\s*fromUri\s*=\s*\'([^\']+)\'', c)
	if not rx_from_uri:
		dbg(conf.get('debug'), 'not found', 'formUri')
		return None
	from_uri = to_b(rx_from_uri.group(1)).decode('unicode_escape').strip()
	if from_uri.startswith('http'):
		return from_uri
	if not rx_base_url:
		dbg(conf.get('debug'), 'not found', 'baseUri')
		if current_url:
			return urljoin(current_url, from_uri)
		return from_uri
	base_url = to_b(rx_base_url.group(1)).decode('unicode_escape').strip()
	return base_url + from_uri

def parse_url(url):
	purl = list(urlparse(url))
	return (purl[0], purl[1].split(':')[0])

def send_req(conf, s, name, url, data, **kwargs):
	dbg(conf.get('debug'), '{0}.request'.format(name), url)
	dbg_form(conf, 'send.req.data', data)
	expected_url = kwargs.get('expected_url')
	if expected_url:
		purl, pexp = parse_url(url), parse_url(expected_url)
		if purl != pexp:
			err('{0}: unexpected url found {1} != {2}'.format(name, purl, pexp))
	do_json = True if kwargs.get('json') else False
	headers = {}
	if do_json:
		data = json.dumps(data)
		headers['Accept'] = 'application/json'
		headers['Content-Type'] = 'application/json'
	if kwargs.get('get'):
		r = s.get(url, headers=headers,
			verify=kwargs.get('verify', True))
	else:
		r = s.post(url, data=data, headers=headers,
			verify=kwargs.get('verify', True))
	hdump = '\n'.join([k + ': ' + v for k, v in sorted(r.headers.items())])
	rr = 'status: {0}\n\n{1}\n\n{2}'.format(r.status_code, hdump, r.text)
	can_fail = True if kwargs.get('can_fail', False) else False
	if not can_fail and r.status_code != 200:
		err('{0}.request failed.\n{1}'.format(name, rr))
	dbg(conf.get('debug'), '{0}.response'.format(name), rr)
	if do_json:
		return r.status_code, r.headers, parse_rjson(r)
	return r.status_code, r.headers, r.text

def paloalto_prelogin(conf, s, gateway_url=None):
	verify = None
	if gateway_url:
		# 2nd round or direct gateway: use gateway
		log('prelogin request [gateway_url]')
		url = '{0}/ssl-vpn/prelogin.esp'.format(gateway_url)
		verify = conf.get('vpn_url_cert')
	else:
		# 1st round: use portal
		log('prelogin request [vpn_url]')
		url = '{0}/global-protect/prelogin.esp'.format(conf.get('vpn_url'))
		if conf.get('openconnect_certs') and os.path.getsize(conf.get('openconnect_certs').name) > 0:
			verify = conf.get('openconnect_certs').name
	_, _h, c = send_req(conf, s, 'prelogin', url, {}, get=True, verify=verify)
	x = parse_xml(c)
	saml_req = x.find('.//saml-request')
	if saml_req is None:
		msg = x.find('.//msg')
		if msg is not None:
			msg = msg.text
		if msg is not None:
			msg = msg.strip()
		else:
			msg = 'Probably SAML is disabled at the portal? Or you need a certificate? Try another_dance=0 with some concrete gateway instead.'
		err('did not find saml request.\n{0}'.format(msg))
	if len(saml_req.text.strip()) == 0:
		err('empty saml request')
	try:
		saml_raw = base64.b64decode(saml_req.text)
	except Exception as e:
		err('failed to decode saml request: ' + e)
	dbg(conf.get('debug'), 'prelogin.decoded', saml_raw)
	saml_xml = parse_html(saml_raw)
	return saml_xml

def okta_saml(conf, s, saml_xml):
	log('okta saml request [okta_url]')
	url, data = parse_form(saml_xml)
	dbg_form(conf, 'okta.saml request', data)
	_, _h, c = send_req(conf, s, 'saml', url, data,
		expected_url=conf.get('okta_url'), verify=conf.get('okta_url_cert'))
	redirect_url = get_redirect_url(conf, c, url)
	if redirect_url is None:
		err('did not find redirect url')
	return redirect_url

def okta_auth(conf, s, stateToken = None):
	log('okta auth request [okta_url]')
	url = '{0}/api/v1/authn'.format(conf.get('okta_url'))
	data = {
		'username': conf.get('username'),
		'password': conf.get('password'),
		'options': {
			'warnBeforePasswordExpired':True,
			'multiOptionalFactorEnroll':True
		}
	} if stateToken is None else {
		'stateToken': stateToken
	}
	_, _h, j = send_req(conf, s, 'auth', url, data, json=True,
		verify=conf.get('okta_url_cert'))

	while True:
		ok, r = okta_transaction_state(conf, s, j)
		if ok == True:
			return r
		j = r

def okta_transaction_state(conf, s, j):
	# https://developer.okta.com/docs/api/resources/authn#transaction-state
	status = j.get('status', '').strip().lower()
	dbg(conf.get('debug'), 'status', status)
	# status: unauthenticated
	# status: password_warn
	if status == 'password_warn':
		log('password expiration warning')
		url = j.get('_links', {}).get('skip', {}).get('href', '').strip()
		if len(url) == 0:
			err('skip url not found')
		state_token = j.get('stateToken', '').strip()
		if len(state_token) == 0:
			err('empty state token')
		data = {'stateToken': state_token}
		_, _h, j = send_req(conf, s, 'skip', url, data, json=True,
			expected_url=conf.get('okta_url'), verify=conf.get('okta_url_cert'))
		return False, j
	# status: password_expired
	# status: recovery
	# status: recovery_challenge
	# status: password_reset
	# status: locked_out
	# status: mfa_enroll
	# status: mfa_enroll_activate
	# status: mfa_required
	if status == 'mfa_required':
		j = okta_mfa(conf, s, j)
		return False, j
	# status: mfa_challenge
	# status: success
	if status == 'success':
		session_token = j.get('sessionToken', '').strip()
		if len(session_token) == 0:
			err('empty session token')
		return True, session_token
	print(j)
	err('unknown status: {0}'.format(status))

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
			'priority': mfa_priority(conf, factor_type, provider),
			'url': factor_url})
	dbg(conf.get('debug'), 'factors', *factors)
	if len(factors) == 0:
		err('no factors found')
	for f in sorted(factors, key=lambda x: x.get('priority', 0), reverse=True):
		#print(f)
		ftype = f.get('type')
		fprovider = f.get('provider')
		if ftype == 'token:software:totp' or (ftype, fprovider) == ('token', 'symantec'):
			r = okta_mfa_totp(conf, s, f, state_token)
		elif ftype == 'sms':
			r = okta_mfa_sms(conf, s, f, state_token)
		elif ftype == 'push':
			r = okta_mfa_push(conf, s, f, state_token)
		elif ftype == 'webauthn':
			r = okta_mfa_webauthn(conf, s, f, state_token)
		else:
			r = None
		if r is not None:
			return r
	err('no factors processed')

def okta_mfa_totp(conf, s, factor, state_token):
	provider = factor.get('provider', '')
	secret = conf.get('totp.{0}'.format(provider), '') or ''
	code = None
	if len(secret) == 0:
		code = input('{0} TOTP: '.format(provider)).strip()
	else:
		if not have_pyotp:
			err('Need pyotp package, consider doing \'pip install pyotp\' (or similar)')
		totp = pyotp.TOTP(secret)
		code = totp.now()
	code = code or ''
	if len(code) == 0:
		return None
	data = {
		'factorId': factor.get('id'),
		'stateToken': state_token,
		'passCode': code
	}
	log('mfa {0} totp request: {1} [okta_url]'.format(provider, code))
	_, _h, j = send_req(conf, s, 'totp mfa', factor.get('url'), data, json=True,
		expected_url=conf.get('okta_url'), verify=conf.get('okta_url_cert'))
	return j

def okta_mfa_sms(conf, s, factor, state_token):
	provider = factor.get('provider', '')
	data = {
		'factorId': factor.get('id'),
		'stateToken': state_token
	}
	log('mfa {0} sms request [okta_url]'.format(provider))
	_, _h, j = send_req(conf, s, 'sms mfa (1)', factor.get('url'), data, json=True,
		expected_url=conf.get('okta_url'), verify=conf.get('okta_url_cert'))
	code = input('{0} SMS verification code: '.format(provider)).strip()
	if len(code) == 0:
		return None
	data['passCode'] = code
	log('mfa {0} sms request [okta_url]'.format(provider))
	_, _h, j = send_req(conf, s, 'sms mfa (2)', factor.get('url'), data, json=True,
		expected_url=conf.get('okta_url'), verify=conf.get('okta_url_cert'))
	return j

def okta_mfa_push(conf, s, factor, state_token):
	provider = factor.get('provider', '')
	data = {
		'factorId': factor.get('id'),
		'stateToken': state_token,
	}
	log('mfa {0} push request [okta_url]'.format(provider))
	status = 'MFA_CHALLENGE'
	counter = 0
	while status == 'MFA_CHALLENGE':
		_, _h, j = send_req(conf, s, 'push mfa ({0})'.format(counter),
			factor.get('url'), data, json=True,
			expected_url=conf.get('okta_url'), verify=conf.get('okta_url_cert'))
		status = j.get('status', '').strip()
		dbg(conf.get('debug'), 'status', status)
		if status == 'MFA_CHALLENGE':
			time.sleep(3.33)
		counter += 1
	return j

def okta_mfa_webauthn(conf, s, factor, state_token):
	if not have_fido:
		err('Need fido2 package(s) for webauthn. Consider doing `pip install fido2` (or similar)')
	devices = list(CtapHidDevice.list_devices())
	if not devices:
		err('webauthn configured, but no U2F devices found')
		return None
	provider = factor.get('provider', '')
	log('mfa {0} challenge request [okta_url]'.format(provider))
	data = {
		'stateToken': state_token
	}
	_, _h, j = send_req(conf, s, 'webauthn mfa challenge', factor.get('url'), data, json=True,
		expected_url=conf.get('okta_url'), verify=conf.get('okta_url_cert'))
	factor = j['_embedded']['factor']
	profile = factor['profile']
	purl = list(urlparse(conf.get('okta_url')))
	rpid = purl[1].split(':')[0]
	origin = '{0}://{1}'.format(purl[0], rpid)
	challenge = factor['_embedded']['challenge']['challenge']
	credentialId = websafe_decode(profile['credentialId'])
	allow_list = [{'type': 'public-key', 'id': credentialId}]
	for dev in devices:
		client = Fido2Client(dev, origin)
		print('!!! Touch the flashing U2F device to authenticate... !!!')
		try:
			result = client.get_assertion(rpid, challenge, allow_list)
			dbg(conf.get('debug'), 'assertion.result', result)
			break
		except:
			traceback.print_exc(file=sys.stderr)
			result = None
	if not result:
		return None
	assertion, client_data = result[0][0], result[1] # only one cred in allowList, so only one response.
	data = {
		'stateToken': state_token,
		'clientData': to_u(base64.b64encode(client_data)),
		'signatureData': to_u(base64.b64encode(assertion.signature)),
		'authenticatorData': to_u(base64.b64encode(assertion.auth_data))
	}
	log('mfa {0} signature request [okta_url]'.format(provider))
	_, _h, j = send_req(conf, s, 'uf2 mfa signature', j['_links']['next']['href'], data, json=True,
		expected_url=conf.get('okta_url'), verify=conf.get('okta_url_cert'))
	return j

def okta_redirect(conf, s, session_token, redirect_url):
	rc = 0
	form_url, form_data = None, {}
	while True:
		if rc > 10:
			err('redirect rabbit hole is too deep...')
		rc += 1
		if redirect_url:
			data = {
				'checkAccountSetupComplete': 'true',
				'report': 'true',
				'token': session_token,
				'redirectUrl': redirect_url
			}
			url = '{0}/login/sessionCookieRedirect'.format(conf.get('okta_url'))
			log('okta redirect request {0} [okta_url]'.format(rc))
			_, h, c = send_req(conf, s, 'redirect', url, data,
				verify=conf.get('okta_url_cert'))
			state_token = get_state_token(conf, c, url)
			redirect_url = get_redirect_url(conf, c, url)
			if redirect_url:
				form_url, form_data = None, {}
			else:
				xhtml = parse_html(c)
				form_url, form_data = parse_form(xhtml, url)
				dbg_form(conf, 'okta.redirect request {0}'.format(rc), data)
			if state_token is not None:
				log('stateToken: {0}'.format(state_token))
				okta_auth(conf, s, state_token)
		elif form_url:
			log('okta redirect form request [vpn_url]')
			purl, pexp = parse_url(form_url), parse_url(conf.get('vpn_url'))
			if purl != pexp:
				# NOTE: redirect to nearest (geo) portal/gateway without any prior knowledge
				warn('{0}: unexpected url found {1} != {2}'.format('redirect form', purl, pexp))
				_, h, c = send_req(conf, s, 'redirect form', form_url, form_data)
			else:
				_, h, c = send_req(conf, s, 'redirect form', form_url, form_data,
					expected_url=conf.get('vpn_url'), verify=conf.get('vpn_url_cert'))
		saml_username = h.get('saml-username', '').strip()
		prelogin_cookie = h.get('prelogin-cookie', '').strip()
		if saml_username and prelogin_cookie:
			saml_auth_status = h.get('saml-auth-status', '').strip()
			saml_slo = h.get('saml-slo', '').strip()
			dbg(conf.get('debug'), 'saml prop', [saml_auth_status, saml_slo])
			return saml_username, prelogin_cookie

def paloalto_getconfig(conf, s, username = None, prelogin_cookie = None, can_fail = False):
	log('getconfig request [vpn_url]')
	url = '{0}/global-protect/getconfig.esp'.format(conf.get('vpn_url'))
	data = {
        #'jnlpReady': 'jnlpReady',
        #'ok': 'Login',
        #'direct': 'yes',
		'clientVer': '4100',
        #'prot': 'https:',
		'clientos': 'Windows',
		'os-version': 'Microsoft Windows 10 Pro, 64-bit',
        #'server': '',
		'computer': 'DESKTOP',
        #'preferred-ip': '',
		'inputStr': '',
		'user': username or conf['username'],
		'passwd': '' if prelogin_cookie else conf['password'],
		'clientgpversion': '4.1.0.98',
		# 'host-id': '00:11:22:33:44:55'
		'prelogin-cookie': prelogin_cookie or '',
		'ipv6-support': 'yes'
	}
	sc, _h, c = send_req(conf, s, 'getconfig', url, data,
		verify=conf.get('vpn_url_cert'), can_fail=can_fail)
	if sc != 200:
		return sc, '', ''
	x = parse_xml(c)
	xtmp = x.find('.//portal-userauthcookie')
	if xtmp is None:
		err('did not find portal-userauthcookie')
	portal_userauthcookie = xtmp.text
	if len(portal_userauthcookie) == 0:
		err('empty portal_userauthcookie')
	gateways = {}
	xtmp = x.find('.//gateways//external//list')
	if xtmp is not None:
		for entry in xtmp:
			gw_name = entry.get('name')
			gw_desc = (entry.xpath('./description/text()') or [''])[0]
			gateways[gw_name] = gw_desc
	xtmp = x.find('.//root-ca')
	if xtmp is not None:
		for entry in xtmp:
			cert = entry.find('.//cert').text
			conf['openconnect_certs'].write(to_b(cert))
		conf['openconnect_certs'].flush()
	return 200, portal_userauthcookie, gateways

# Combined first half of okta_saml with second half of okta_redirect
def okta_saml_2(conf, s, gateway_url, saml_xml):
	log('okta saml request (2) [okta_url]')
	url, data = parse_form(saml_xml)
	dbg_form(conf, 'okta.saml request(2)', data)
	_, h, c = send_req(conf, s, 'okta saml request (2)', url, data,
		expected_url=conf.get('okta_url'), verify=conf.get('okta_url_cert'))
	xhtml = parse_html(c)
	url, data = parse_form(xhtml)
	dbg_form(conf, 'okta.saml request(2)', data)
	log('okta redirect form request (2) [gateway]')
	verify = None
	if conf.get('openconnect_certs') and os.path.getsize(conf.get('openconnect_certs').name) > 0:
		verify = conf.get('openconnect_certs').name
	_, h, c = send_req(conf, s, 'okta redirect form (2)', url, data,
		expected_url=gateway_url, verify=verify)
	saml_username = h.get('saml-username', '').strip()
	if len(saml_username) == 0:
		err('saml-username empty')
	prelogin_cookie = h.get('prelogin-cookie', '').strip()
	if len(prelogin_cookie) == 0:
		err('prelogin-cookie empty')

	return saml_username, prelogin_cookie

def output_gateways(gateways):
	print("Gateways:")
	for k in sorted(gateways.keys()):
		print("\t{0} {1}".format(k, gateways[k]))

def choose_gateway_url(conf, gateways):
	gateway_url = conf.get('gateway_url', '').strip()
	if gateway_url:
		return gateway_url
	if len(gateways) == 0:
		err('no available gateways')
	gateway_name = conf.get('gateway', '').strip()
	gateway_host = None
	for k in gateways.keys():
		if gateways[k] == gateway_name:
			gateway_host = k
			break
	if not gateway_host:
		# this just grabs an arbitrary gateway
		gateway_host = gateways.keys().pop()
	return 'https://{0}'.format(gateway_host)

def main():

	parser = argparse.ArgumentParser(description="""
	This is an OpenConnect wrapper script that automates connecting to a
	PaloAlto Networks GlobalProtect VPN using Okta 2FA.""")

	parser.add_argument('conf_file',
		help='e.g. ~/.config/gp-okta.conf')
	parser.add_argument('--gpg-decrypt', action='store_true',
		help='use gpg and settings from gpg-home to decrypt gpg encrypted conf_file')
	parser.add_argument('--gpg-home', default=os.path.expanduser('~/.gnupg'))
	parser.add_argument('--list-gateways', default=False, action='store_true',
		help='get list of gateways from portal')
	parser.add_argument('--quiet', default=False, action='store_true',
		help='disable verbose logging')
	args = parser.parse_args()

	global quiet
	quiet = args.quiet

	assert os.path.exists(args.conf_file)
	assert not args.gpg_decrypt or os.path.isdir(args.gpg_home)

	config_contents = ''
	with io.open(args.conf_file, 'rb') as fp:
		config_contents = fp.read()

	if args.conf_file.endswith('.gpg') and not args.gpg_decrypt:
		err('conf file looks like gpg encrypted. Did you forget the --gpg-decrypt?')

	if args.gpg_decrypt:
		if not have_gnupg:
			err('Need gnupg package for reading gnupg encrypted files. Consider doing `pip install python-gnupg` (or similar)')
		gpg = gnupg.GPG(gnupghome=args.gpg_home)
		decrypted_contents = gpg.decrypt(config_contents)

		if not decrypted_contents.ok:
			print('[ERROR] failed to decrypt config file:', file=sys.stderr)
			print('[ERROR]     status: {}'.format(decrypted_contents.status), file=sys.stderr)
			print('[ERROR]     error: {}'.format(decrypted_contents.stderr), file=sys.stderr)
			sys.exit(1)

		config_contents = decrypted_contents.data

	conf = load_conf(config_contents)

	s = requests.Session()
	s.headers['User-Agent'] = 'PAN GlobalProtect'

	if conf.get('client_cert'):
		s.cert = conf.get('client_cert')

	if args.list_gateways:
		log('listing gateways')
		sc, _, gateways = paloalto_getconfig(conf, s, can_fail=True)
		if sc == 200:
			output_gateways(gateways)
			return 0
		else:
			log('gateway list requires authentication')

	another_dance = conf.get('another_dance', '').lower() in ['1', 'true']
	gateway_url = conf.get('gateway_url', '').strip()
	gateway_name = conf.get('gateway', '').strip()

	if gateway_url and not another_dance:
		vpn_url = gateway_url
		if vpn_url != conf.get('vpn_url'):
			log('Discarding \'vpn_url\', as concrete \'gateway_url\' is given and another_dance = 0')
			conf['vpn_url'] = vpn_url

	userauthcookie = None

	if another_dance or not gateway_url:
		saml_xml = paloalto_prelogin(conf, s)
	else:
		saml_xml = paloalto_prelogin(conf, s, gateway_url)

	redirect_url = okta_saml(conf, s, saml_xml)
	token = okta_auth(conf, s)
	log('sessionToken: {0}'.format(token))
	saml_username, prelogin_cookie = okta_redirect(conf, s, token, redirect_url)
	if args.list_gateways:
		log('listing gateways')
		sc, _, gateways = paloalto_getconfig(conf, s, saml_username, prelogin_cookie)
		if sc == 200:
			output_gateways(gateways)
			return 0
		else:
			err('could not list gateways')

	if another_dance or not gateway_url:
		_, userauthcookie, gateways = paloalto_getconfig(conf, s, saml_username, prelogin_cookie)
		gateway_url = choose_gateway_url(conf, gateways)

	log('portal-userauthcookie: {0}'.format(userauthcookie))
	log('gateway: {0}'.format(gateway_url))
	log('saml-username: {0}'.format(saml_username))
	log('prelogin-cookie: {0}'.format(prelogin_cookie))

	if another_dance:
		# 1st step: dance with the portal, 2nd step: dance with the gateway
		saml_xml = paloalto_prelogin(conf, s, gateway_url)
		saml_username, prelogin_cookie = okta_saml_2(conf, s, gateway_url, saml_xml)
		log('saml-username (2): {0}'.format(saml_username))
		log('prelogin-cookie (2): {0}'.format(prelogin_cookie))

	if (not userauthcookie or userauthcookie == 'empty') and prelogin_cookie != 'empty':
	    cookie_type = 'gateway:prelogin-cookie'
	    cookie = prelogin_cookie
	else:
	    cookie_type = 'portal:portal-userauthcookie'
	    cookie = userauthcookie

	username = saml_username

	cmd = conf.get('openconnect_cmd', 'openconnect')
	cmd += ' --protocol=gp -u \'{0}\''
	cmd += ' --usergroup {1}'
	if conf.get('client_cert'):
		cmd += ' --certificate=\'{0}\''.format(conf.get('client_cert'))
	if conf.get('openconnect_certs') and os.path.getsize(conf.get('openconnect_certs').name) > 0:
		cmd += ' --cafile=\'{0}\''.format(conf.get('openconnect_certs').name)
	cmd += ' --passwd-on-stdin ' + conf.get('openconnect_args', '') + ' \'{2}\''
	cmd = cmd.format(username, cookie_type,
		gateway_url if conf.get('another_dance', '').lower() in ['1', 'true'] else conf.get('vpn_url'))

	bugs = ''
	if conf.get('bug.nl', '').lower() in ['1', 'true']:
		bugs += '\\n'
	if conf.get('bug.username', '').lower() in ['1', 'true']:
		bugs += '{0}\\n'.format(username.replace('\\', '\\\\'))
	if len(gateway_name) > 0:
		pcmd = 'printf \'' + bugs + '{0}\\n{1}\''.format(cookie, gateway_name)
	else:
		pcmd = 'printf \'' + bugs + '{0}\''.format(cookie)
	print()
	if conf.get('execute', '').lower() in ['1', 'true']:
		cmd = shlex.split(cmd)
		cmd = [os.path.expandvars(os.path.expanduser(x)) for x in cmd]
		pp = subprocess.Popen(shlex.split(pcmd), stdout=subprocess.PIPE)
		cp = subprocess.Popen(cmd, stdin=pp.stdout, stdout=sys.stdout)
		pp.stdout.close()
		# Do not abort on SIGINT. openconnect will perform proper exit & cleanup
		signal.signal(signal.SIGINT, signal.SIG_IGN)
		cp.communicate()
	else:
		print('{0} | {1}'.format(pcmd, cmd))
	return 0


if __name__ == '__main__':
	sys.exit(main())
