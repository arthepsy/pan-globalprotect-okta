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
from __future__ import print_function
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

try:
	# from typing import IO, BinaryIO
	from typing import Any, Dict, List, Union, Tuple
	from typing import Optional, NoReturn
except ImportError:
	pass

# Optional: fido2 support (webauthn via Yubikey)
have_fido = False
try:
	from fido2.utils import websafe_decode
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

def _type_err(v, target):
	# type: (Any, text_type) -> TypeError
	return TypeError('cannot convert {0} to {1}'.format(type(v), target))

def to_b(v):
	# type: (Union[binary_type, text_type]) -> binary_type
	if isinstance(v, binary_type):
		return v
	if isinstance(v, text_type):
		return v.encode('utf-8')
	raise _type_err(v, 'bytes')

def to_u(v):
	# type: (Union[text_type, binary_type]) -> text_type
	if isinstance(v, text_type):
		return v
	if isinstance(v, binary_type):
		return v.decode('utf-8')
	raise _type_err(v, 'unicode text')

def to_n(v):
	# type: (Union[text_type, binary_type]) -> str
	if isinstance(v, str):
		return v
	if isinstance(v, text_type):
		return v.encode('utf-8')
	if isinstance(v, binary_type):
		return v.decode('utf-8')
	raise _type_err(v, 'native text')

quiet = False

def log(s):
	# type: (str) -> None
	if not quiet:
		print(u'[INFO] {0}'.format(s))

def warn(s):
	# type: (str) -> None
	if not quiet:
		print(u'[WARN] {0}'.format(s))

def dbg(d, h, *xs):
	# type: (Any, str, Union[str, List[str], Dict[str, Any]]) -> None
	if quiet:
		return
	if not d:
		return
	for x in xs:
		if not isinstance(x, dict) and not isinstance(x, list):
			for line in x.split('\n'):
				print(u'[DEBUG] {0}: {1}'.format(h, line))
		else:
			print(u'[DEBUG] {0}: {1}'.format(h, x))

def dbg_form(conf, name, data):
	# type: (Conf, str, Dict[str, str]) -> None
	if not conf.debug:
		return
	for k in data:
		dbg(True, name, '{0}: {1}'.format(k, data[k]))
		if k in [u'SAMLRequest', u'SAMLResponse']:
			try:
				saml_raw = to_n(base64.b64decode(data[k]).decode('ascii'))
				dbg(True, name, '{0}.decoded: {1}'.format(k,  saml_raw))
			except Exception:
				pass


def err(s):
	# type: (str) -> NoReturn
	print('[ERROR] {0}'.format(s), file=sys.stderr)
	sys.exit(1)

def parse_xml(xml):
	# type: (str) -> etree._Element
	try:
		rxml = bytes(bytearray(xml, encoding='utf-8'))
		parser = etree.XMLParser(ns_clean=True, recover=True)
		return etree.fromstring(rxml, parser)
	except Exception as e:
		err('failed to parse xml: {0}'.format(e))

def parse_html(html):
	# type: (str) -> etree._Element
	try:
		parser = etree.HTMLParser()
		return etree.fromstring(html, parser)
	except Exception as e:
		err('failed to parse html: {0}'.format(e))

def parse_rjson(r):
	# type: (requests.Response) -> Dict[str, Any]
	try:
		j = r.json() # type: Dict[str, Any]
		return j
	except Exception as e:
		err('failed to parse json: {0}'.format(e))

def parse_form(html, current_url = None):
	# type: (etree._Element, Optional[str]) -> Tuple[str, Dict[str, str]]
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

class Conf(object):
	def __init__(self):
		# type: () -> None
		self._store = {} # type: Dict[str, str]
		self._lines = {} # type: Dict[str, int]
		self.debug = False
		self._session = None # type: Optional[requests.Session]
		self.vpn_url = ''  # for reassignment
		self.certs = ''  # for filename
	
	def __getattr__(self, name):
		# type: (str) -> str
		if name in self._store:
			return self._store[name]
		return ''

	def get_session(self, name):
		# type: (str) -> requests.Session
		if self._session is None:
			raise Exception('session not defined')
		name = name.lower()
		if name not in ['okta', 'portal', 'gateway']:
			raise Exception('unknonw session: {0}'.format(name))
		s = self._session
		if name == 'okta':
			if self.okta_cli_cert:
				s.cert = self.okta_cli_cert
		if self.vpn_cli_cert:
			s.cert = self.vpn_cli_cert
		return s

	def get_value(self, name):
		# type: (str) -> str
		return to_n(getattr(self, name))
	
	def get_bool(self, name):
		# type: (str) -> bool
		v = self.get_value(name)
		return v.lower() in ['1', 'true']

	def add_cert(self, cert):
		# type: (str) -> None
		if not cert:
			return
		if not self.certs:
			if 'certs' in self._store:
				self.certs_fh = io.open(self._store['certs'], 'wb')
			else:
				self.certs_fh = tempfile.NamedTemporaryFile(prefix='gpvpn_', delete=False)
				log('using temporary file {0} for storing certificates'.format(self.certs_fh.name))
			self.certs = self.certs_fh.name
		self.certs_fh.write(to_b(cert))
		self.certs_fh.flush()
	
	def get_cert(self, name, default_verify=True):
		# type: (str, bool) -> Union[str, bool]
		name = '{0}_cert'.format(name)
		if name in self._store:
			return self._store[name]
		return default_verify
	
	def get_line(self, name):
		# type: (str) -> int
		if name in self._lines:
			return self._lines[name]
		return 0

	@classmethod
	def from_data(cls, content):
		# type: (str) -> Conf
		conf = cls()
		log('load conf')
		keys = ['vpn_url', 'username', 'password', 'okta_url']
		line_nr = 0
		for rline in to_n(content).split('\n'):
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
				conf._store[k] = v
				conf._lines[k] = line_nr
		for k, v in os.environ.items():
			k = k.lower()
			if k.startswith('gp_'):
				k = k[3:]
				if len(k) == 0:
					continue
				conf._store[k] = v.strip()
		if len(conf._store.get('username', '').strip()) == 0:
			conf._store['username'] = input('username: ').strip()
		if len(conf._store.get('password', '').strip()) == 0:
			conf._store['password'] = getpass.getpass('password: ').strip()
		for k in conf._store.keys():
			if not k.endswith('_cert'):
				continue
			cert_file = conf._store.get(k, '').strip()
			if cert_file:
				cert_file = os.path.expandvars(os.path.expanduser(cert_file))
				if not os.path.exists(cert_file):
					err('configured "{0}" file "{1}" does not exist'.format(k, cert_file))
				if k.endswith('_cli_cert'):
					continue
				with io.open(cert_file, 'rb') as fp:
					conf.add_cert(fp.read())
		for k in keys:
			if k not in conf._store:
				err('missing configuration key: {0}'.format(k))
			else:
				if len(conf._store[k].strip()) == 0:
					err('empty configuration key: {0}'.format(k))
			if k == 'vpn_url':
				setattr(conf, k, conf._store[k].strip())
		conf.debug = conf._store.get('debug', '').lower() in ['1', 'true']
		s = requests.Session()
		s.headers['User-Agent'] = 'PAN GlobalProtect'
		conf._session = s
		return conf

def mfa_priority(conf, ftype, fprovider):
	# type: (Conf, str, str) -> int
	if ftype == 'token:software:totp' or (ftype, fprovider) == ('token', 'symantec'):
		ftype = 'totp'
	if ftype not in ['totp', 'sms', 'push', 'webauthn']:
		return 0
	mfa_order = conf.mfa_order.split()
	if ftype in mfa_order:
		priority = (10 - mfa_order.index(ftype)) * 100
	else:
		priority = 0
	value = conf.get_value('{0}.{1}'.format(ftype, fprovider)) # type: Optional[str]
	if ftype in ('sms', 'webauthn'):
		if not (value or '').lower() in ['1', 'true']:
			value = None
	line_nr = conf.get_line('{0}.{1}'.format(ftype, fprovider))
	if value is None:
		priority += 0
	elif len(value) == 0:
		priority += (128 - line_nr)
	else:
		priority += (512 - line_nr)
	return priority

def get_state_token(conf, c):
	# type: (Conf, str) -> Optional[str]
	rx_state_token = re.search(r'var\s*stateToken\s*=\s*\'([^\']+)\'', c)
	if not rx_state_token:
		dbg(conf.debug, 'not found', 'stateToken')
		return None
	state_token = to_n(to_b(rx_state_token.group(1)).decode('unicode_escape').strip())
	return state_token

def get_redirect_url(conf, c, current_url = None):
	# type: (Conf, str, Optional[str]) -> Optional[str]
	rx_base_url = re.search(r'var\s*baseUrl\s*=\s*\'([^\']+)\'', c)
	rx_from_uri = re.search(r'var\s*fromUri\s*=\s*\'([^\']+)\'', c)
	if not rx_from_uri:
		dbg(conf.debug, 'not found', 'formUri')
		return None
	from_uri = to_n(to_b(rx_from_uri.group(1)).decode('unicode_escape').strip())
	if from_uri.startswith('http'):
		return from_uri
	if not rx_base_url:
		dbg(conf.debug, 'not found', 'baseUri')
		if current_url:
			return urljoin(current_url, from_uri)
		return from_uri
	base_url = to_n(to_b(rx_base_url.group(1)).decode('unicode_escape').strip())
	return base_url + from_uri

def parse_url(url):
	# type: (str) -> Tuple[str, str]
	purl = list(urlparse(url))
	return (purl[0], purl[1].split(':')[0])

def _send_req_pre(conf, name, url, data, expected_url=None):
	# type: (Conf, str, str, Dict[str, Any], Optional[str]) -> None
	dbg(conf.debug, '{0}.request'.format(name), url)
	dbg_form(conf, 'send.req.data', data)
	if expected_url:
		purl, pexp = parse_url(url), parse_url(expected_url)
		if purl != pexp:
			err('{0}: unexpected url found {1} != {2}'.format(name, purl, pexp))

def _send_req_post(conf, r, name, can_fail=False):
	# type: (Conf, requests.Response, str, bool) -> None
	hdump = '\n'.join([k + ': ' + v for k, v in sorted(r.headers.items())])
	rr = 'status: {0}\n\n{1}\n\n{2}'.format(r.status_code, hdump, r.text)
	if not can_fail and r.status_code != 200:
		err('{0}.request failed.\n{1}'.format(name, rr))
	dbg(conf.debug, '{0}.response'.format(name), rr)

def send_req(conf, dest, name, url, data, get=False, expected_url=None, verify=True, can_fail=False):
	# type: (Conf, str, str, str, Dict[str, Any], bool, Optional[str], Union[bool, str], bool) -> Tuple[int, requests.structures.CaseInsensitiveDict[str], str]
	_send_req_pre(conf, name, url, data, expected_url)
	s = conf.get_session(dest)
	if get:
		r = s.get(url, verify=verify)
	else:
		r = s.post(url, data=data, verify=verify)
	_send_req_post(conf, r, name, can_fail)
	return r.status_code, r.headers, r.text

def send_json_req(conf, dest, name, url, data, get=False, expected_url=None, verify=True, can_fail=False):
	# type: (Conf, str, str, str, Dict[str, Any], bool, Optional[str], Union[bool, str], bool) -> Tuple[int, requests.structures.CaseInsensitiveDict[str], Dict[str, Any]]
	_send_req_pre(conf, name, url, data, expected_url)
	headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
	s = conf.get_session(dest)
	if get:
		r = s.get(url, headers=headers, verify=verify)
	else:
		r = s.post(url, headers=headers, json=data, verify=verify)
	_send_req_post(conf, r, name, can_fail)
	return r.status_code, r.headers, parse_rjson(r)

def paloalto_prelogin(conf, gateway_url=None):
	# type: (Conf, Optional[str]) -> etree._Element
	verify = True # type: Union[str, bool]
	dest = 'portal'
	if gateway_url:
		# 2nd round or direct gateway: use gateway
		log('prelogin request [gateway_url]')
		dest = 'gateway'
		url = '{0}/ssl-vpn/prelogin.esp'.format(gateway_url)
		if conf.certs:
			verify = conf.certs
		else:
			verify = True
	else:
		# 1st round: use portal
		log('prelogin request [vpn_url]')
		url = '{0}/global-protect/prelogin.esp'.format(conf.vpn_url)
		verify = conf.get_cert('vpn_url', True)
	_, _h, c = send_req(conf, dest, 'prelogin', url, {}, get=True, verify=verify)
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
		saml_raw = to_n(base64.b64decode(saml_req.text).decode('ascii'))
	except Exception as e:
		err('failed to decode saml request: {0}'.format(e))
	dbg(conf.debug, 'prelogin.decoded', saml_raw)
	saml_xml = parse_html(saml_raw)
	return saml_xml

def okta_saml(conf, saml_xml):
	# type: (Conf, str) -> str
	log('okta saml request [okta_url]')
	url, data = parse_form(saml_xml)
	dbg_form(conf, 'okta.saml request', data)
	_, _h, c = send_req(conf, 'okta', 'saml', url, data,
		expected_url=conf.okta_url, verify=conf.get_cert('okta_url', True))
	redirect_url = get_redirect_url(conf, c, url)
	if redirect_url is None:
		err('did not find redirect url')
	return redirect_url

def okta_auth(conf, stateToken = None):
	# type: (Conf, Optional[str]) -> Any
	log('okta auth request [okta_url]')
	url = '{0}/api/v1/authn'.format(conf.okta_url)
	data = {
		'username': conf.username,
		'password': conf.password,
		'options': {
			'warnBeforePasswordExpired':True,
			'multiOptionalFactorEnroll':True
		}
	} if stateToken is None else {
		'stateToken': stateToken
	}
	_, _h, j = send_json_req(conf, 'okta', 'auth', url, data, verify=conf.get_cert('okta_url', True))
	while True:
		ok, r = okta_transaction_state(conf, j)
		if ok:
			return r
		j = r

def okta_transaction_state(conf, j):
	# type: (Conf, Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]
	# https://developer.okta.com/docs/api/resources/authn#transaction-state
	status = j.get('status', '').strip().lower()
	dbg(conf.debug, 'status', status)
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
		_, _h, j = send_json_req(conf, 'okta', 'skip', url, data,
			expected_url=conf.okta_url, verify=conf.get_cert('okta_url', True))
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
		j = okta_mfa(conf, j)
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

def okta_mfa(conf, j):
	# type: (Conf, Dict[str, Any]) -> Dict[str, Any]
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
	dbg(conf.debug, 'factors', *factors)
	if len(factors) == 0:
		err('no factors found')
	for f in sorted(factors, key=lambda x: x.get('priority', 0), reverse=True):
		ftype = f.get('type')
		fprovider = f.get('provider')
		r = None # type: Optional[Dict[str, Any]]
		if ftype == 'token:software:totp' or (ftype, fprovider) == ('token', 'symantec'):
			r = okta_mfa_totp(conf, f, state_token)
		elif ftype == 'sms':
			r = okta_mfa_sms(conf, f, state_token)
		elif ftype == 'push':
			r = okta_mfa_push(conf, f, state_token)
		elif ftype == 'webauthn':
			r = okta_mfa_webauthn(conf, f, state_token)
		if r is not None:
			return r
	err('no factors processed')

def okta_mfa_totp(conf, factor, state_token):
	# type: (Conf, Dict[str, str], str) -> Optional[Dict[str, Any]]
	provider = factor.get('provider', '')
	secret = conf.get_value('totp.{0}'.format(provider))
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
	_, _h, j = send_json_req(conf, 'okta', 'totp mfa', factor.get('url', ''), data,
		expected_url=conf.okta_url, verify=conf.get_cert('okta_url', True))
	return j

def okta_mfa_sms(conf, factor, state_token):
	# type: (Conf, Dict[str, str], str) -> Optional[Dict[str, Any]]
	provider = factor.get('provider', '')
	data = {
		'factorId': factor.get('id'),
		'stateToken': state_token
	}
	log('mfa {0} sms request [okta_url]'.format(provider))
	_, _h, j = send_json_req(conf, 'okta', 'sms mfa (1)', factor.get('url', ''), data,
		expected_url=conf.okta_url, verify=conf.get_cert('okta_url', True))
	code = input('{0} SMS verification code: '.format(provider)).strip()
	if len(code) == 0:
		return None
	data['passCode'] = code
	log('mfa {0} sms request [okta_url]'.format(provider))
	_, _h, j = send_json_req(conf, 'okta', 'sms mfa (2)', factor.get('url', ''), data,
		expected_url=conf.okta_url, verify=conf.get_cert('okta_url', True))
	return j

def okta_mfa_push(conf, factor, state_token):
	# type: (Conf, Dict[str, str], str) -> Optional[Dict[str, Any]]
	provider = factor.get('provider', '')
	data = {
		'factorId': factor.get('id'),
		'stateToken': state_token,
	}
	log('mfa {0} push request [okta_url]'.format(provider))
	status = 'MFA_CHALLENGE'
	counter = 0
	while status == 'MFA_CHALLENGE':
		_, _h, j = send_json_req(conf, 'okta', 'push mfa ({0})'.format(counter),
			factor.get('url', ''), data,
			expected_url=conf.okta_url, verify=conf.get_cert('okta_url', True))
		status = j.get('status', '').strip()
		dbg(conf.debug, 'status', status)
		if status == 'MFA_CHALLENGE':
			time.sleep(3.33)
		counter += 1
	return j

def okta_mfa_webauthn(conf, factor, state_token):
	# type: (Conf, Dict[str, str], str) -> Optional[Dict[str, Any]]
	if not have_fido:
		err('Need fido2 package(s) for webauthn. Consider doing `pip install fido2` (or similar)')
	devices = list(CtapHidDevice.list_devices())
	if not devices:
		err('webauthn configured, but no U2F devices found')
	provider = factor.get('provider', '')
	log('mfa {0} challenge request [okta_url]'.format(provider))
	data = {
		'stateToken': state_token
	}
	_, _h, j = send_json_req(conf, 'okta', 'webauthn mfa challenge', factor.get('url', ''), data,
		expected_url=conf.okta_url, verify=conf.get_cert('okta_url', True))
	rfactor = j['_embedded']['factor']
	profile = rfactor['profile']
	purl = parse_url(conf.okta_url)
	origin = '{0}://{1}'.format(purl[0], purl[1])
	challenge = rfactor['_embedded']['challenge']['challenge']
	credentialId = websafe_decode(profile['credentialId'])
	allow_list = [{'type': 'public-key', 'id': credentialId}]
	for dev in devices:
		client = Fido2Client(dev, origin)
		print('!!! Touch the flashing U2F device to authenticate... !!!')
		try:
			result = client.get_assertion(purl[1], challenge, allow_list)
			dbg(conf.debug, 'assertion.result', result)
			break
		except Exception:
			traceback.print_exc(file=sys.stderr)
			result = None
	if not result:
		return None
	assertion, client_data = result[0][0], result[1] # only one cred in allowList, so only one response.
	data = {
		'stateToken': state_token,
		'clientData': to_n((base64.b64encode(client_data)).decode('ascii')),
		'signatureData': to_n((base64.b64encode(assertion.signature)).decode('ascii')),
		'authenticatorData': to_n((base64.b64encode(assertion.auth_data)).decode('ascii'))
	}
	log('mfa {0} signature request [okta_url]'.format(provider))
	_, _h, j = send_json_req(conf, 'okta', 'uf2 mfa signature', j['_links']['next']['href'], data,
		expected_url=conf.okta_url, verify=conf.get_cert('okta_url', True))
	return j

def okta_redirect(conf, session_token, redirect_url):
	# type: (Conf, str, str) -> Tuple[str, str]
	rc = 0
	form_url = None # type: Optional[str]
	form_data = {} # type: Dict[str, str]
	rurl = redirect_url # type: Optional[str]
	while True:
		if rc > 10:
			err('redirect rabbit hole is too deep...')
		rc += 1
		if rurl:
			data = {
				'checkAccountSetupComplete': 'true',
				'report': 'true',
				'token': session_token,
				'redirectUrl': rurl
			}
			url = '{0}/login/sessionCookieRedirect'.format(conf.okta_url)
			log('okta redirect request {0} [okta_url]'.format(rc))
			_, h, c = send_req(conf, 'okta', 'redirect', url, data,
				verify=conf.get_cert('okta_url', True))
			state_token = get_state_token(conf, c)
			rurl = get_redirect_url(conf, c, url)
			if rurl:
				form_url, form_data = None, {}
			else:
				xhtml = parse_html(c)
				form_url, form_data = parse_form(xhtml, url)
				dbg_form(conf, 'okta.redirect request {0}'.format(rc), data)
			if state_token is not None:
				log('stateToken: {0}'.format(state_token))
				okta_auth(conf, state_token)
		elif form_url:
			log('okta redirect form request [vpn_url]')
			purl, pexp = parse_url(form_url), parse_url(conf.vpn_url)
			if purl != pexp:
				# NOTE: redirect to nearest (geo) gateway without any prior knowledge
				warn('{0}: unexpected url found {1} != {2}'.format('redirect form', purl, pexp))
				verify = True # type: Union[str, bool]
				if conf.certs:
					verify = conf.certs
				_, h, c = send_req(conf, 'gateway', 'redirect form', form_url, form_data, verify=verify)
			else:
				_, h, c = send_req(conf, 'portal', 'redirect form', form_url, form_data,
					expected_url=conf.vpn_url, verify=conf.get_cert('vpn_url', True))
		saml_username = h.get('saml-username', '').strip()
		prelogin_cookie = h.get('prelogin-cookie', '').strip()
		if saml_username and prelogin_cookie:
			saml_auth_status = h.get('saml-auth-status', '').strip()
			saml_slo = h.get('saml-slo', '').strip()
			dbg(conf.debug, 'saml prop', [saml_auth_status, saml_slo])
			return saml_username, prelogin_cookie

def paloalto_getconfig(conf, username = None, prelogin_cookie = None, can_fail = False):
	# type: (Conf, Optional[str], Optional[str], bool) -> Tuple[int, str, Dict[str, str]]
	log('getconfig request [vpn_url]')
	url = '{0}/global-protect/getconfig.esp'.format(conf.vpn_url)
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
		'user': username or conf.username,
		'passwd': '' if prelogin_cookie else conf.password,
		'clientgpversion': '4.1.0.98',
		# 'host-id': '00:11:22:33:44:55'
		'prelogin-cookie': prelogin_cookie or '',
		'ipv6-support': 'yes'
	}
	sc, _h, c = send_req(conf, 'portal', 'getconfig', url, data,
		verify=conf.get_cert('vpn_url', True), can_fail=can_fail)
	if sc != 200:
		return sc, '', {}
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
			conf.add_cert(cert)
	return 200, portal_userauthcookie, gateways

# Combined first half of okta_saml with second half of okta_redirect
def okta_saml_2(conf, gateway_url, saml_xml):
	# type: (Conf, str, str) -> Tuple[str, str]
	log('okta saml request (2) [okta_url]')
	url, data = parse_form(saml_xml)
	dbg_form(conf, 'okta.saml request(2)', data)
	_, h, c = send_req(conf, 'okta', 'okta saml request (2)', url, data,
		expected_url=conf.okta_url, verify=conf.get_cert('okta_url', True))
	xhtml = parse_html(c)
	url, data = parse_form(xhtml)
	dbg_form(conf, 'okta.saml request(2)', data)
	log('okta redirect form request (2) [gateway]')
	verify = True # type: Union[str, bool]
	if conf.certs:
		verify = conf.certs
	_, h, c = send_req(conf, 'gateway', 'okta redirect form (2)', url, data,
		expected_url=gateway_url, verify=verify)
	saml_username = h.get('saml-username', '').strip()
	if len(saml_username) == 0:
		err('saml-username empty')
	prelogin_cookie = h.get('prelogin-cookie', '').strip()
	if len(prelogin_cookie) == 0:
		err('prelogin-cookie empty')
	return saml_username, prelogin_cookie

def output_gateways(gateways):
	# type: (Dict[str, str]) -> None
	print("Gateways:")
	for k in sorted(gateways.keys()):
		print("\t{0} {1}".format(k, gateways[k]))

def choose_gateway_url(conf, gateways):
	# type: (Conf, Dict[str, str]) -> str
	if conf.gateway_url:
		return conf.gateway_url
	if len(gateways) == 0:
		err('no available gateways')
	gateway_name = conf.gateway
	gateway_host = None
	for k in gateways.keys():
		if gateways[k] == gateway_name:
			gateway_host = k
			break
	if not gateway_host:
		# this just grabs an arbitrary gateway
		gateway_host = next(iter(gateways))
	return 'https://{0}'.format(gateway_host)

def main():
	# type: () -> int
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

	conf = Conf.from_data(config_contents)

	if args.list_gateways:
		log('listing gateways')
		sc, _, gateways = paloalto_getconfig(conf, can_fail=True)
		if sc == 200:
			output_gateways(gateways)
			return 0
		log('gateway list requires authentication')

	another_dance = conf.another_dance.lower() in ['1', 'true']
	gateway_url = conf.gateway_url
	gateway_name = conf.gateway

	if gateway_url and not another_dance:
		vpn_url = gateway_url
		if vpn_url != conf.vpn_url:
			log('Discarding \'vpn_url\', as concrete \'gateway_url\' is given and another_dance = 0')
			conf.vpn_url = vpn_url

	userauthcookie = None

	if another_dance or not gateway_url:
		saml_xml = paloalto_prelogin(conf)
	else:
		saml_xml = paloalto_prelogin(conf, gateway_url)

	redirect_url = okta_saml(conf, saml_xml)
	token = okta_auth(conf)
	log('sessionToken: {0}'.format(token))
	saml_username, prelogin_cookie = okta_redirect(conf, token, redirect_url)
	if args.list_gateways:
		log('listing gateways')
		sc, _, gateways = paloalto_getconfig(conf, saml_username, prelogin_cookie)
		if sc == 200:
			output_gateways(gateways)
			return 0
		err('could not list gateways')

	if another_dance or not gateway_url:
		_, userauthcookie, gateways = paloalto_getconfig(conf, saml_username, prelogin_cookie)
		gateway_url = choose_gateway_url(conf, gateways)

	log('portal-userauthcookie: {0}'.format(userauthcookie))
	log('gateway: {0}'.format(gateway_url))
	log('saml-username: {0}'.format(saml_username))
	log('prelogin-cookie: {0}'.format(prelogin_cookie))

	if another_dance:
		# 1st step: dance with the portal, 2nd step: dance with the gateway
		saml_xml = paloalto_prelogin(conf, gateway_url)
		saml_username, prelogin_cookie = okta_saml_2(conf, gateway_url, saml_xml)
		log('saml-username (2): {0}'.format(saml_username))
		log('prelogin-cookie (2): {0}'.format(prelogin_cookie))

	if (not userauthcookie or userauthcookie == 'empty') and prelogin_cookie != 'empty':
	    cookie_type = 'gateway:prelogin-cookie'
	    cookie = prelogin_cookie
	else:
	    cookie_type = 'portal:portal-userauthcookie'
	    cookie = userauthcookie or ''

	username = saml_username

	cmd = conf.openconnect_cmd or 'openconnect'
	cmd += ' --protocol=gp -u \'{0}\''
	cmd += ' --usergroup {1}'
	if conf.vpn_cli_cert:
		cmd += ' --certificate=\'{0}\''.format(conf.vpn_cli_cert)
	if conf.certs:
		cmd += ' --cafile=\'{0}\''.format(conf.certs)
	cmd += ' --passwd-on-stdin ' + conf.openconnect_args + ' \'{2}\''
	if conf.certs:
		cmd += '; rm -f \'{0}\''.format(conf.certs)
	cmd = cmd.format(username, cookie_type,
		gateway_url if conf.get_bool('another_dance') else conf.vpn_url)

	pfmt = conf.openconnect_fmt
	if not pfmt:
		pfmt = '<cookie><gateway_name>'
		openconnect_bin = (conf.openconnect_cmd or 'openconnect').split()[-1:][0]
		openconnect_bin = os.path.expandvars(os.path.expanduser(openconnect_bin))
		with open(os.devnull, 'wb') as fnull:
			p  = subprocess.Popen(['command', '-v', openconnect_bin], stdin=subprocess.PIPE, stdout=fnull, stderr=subprocess.STDOUT)
			_ = p.communicate()[0]
		if p.returncode == 0:
			p = subprocess.Popen([openconnect_bin, '-V'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
			o = p.communicate()[0]
			mx = re.search(r'OpenConnect version v(\d)\.(\d+)', to_u(o), flags=re.IGNORECASE)
			if mx:
				vmajor, vminor = mx.groups()
				if vmajor >= '8' and vminor >= '05':
					pfmt = '<cookie><gateway_name><cookie>'
	rmnl = pfmt.endswith('>')
	pfmt = pfmt.replace('<cookie>', cookie + '\\n')
	pfmt = pfmt.replace('<gateway_name>', gateway_name + '\\n' if len(gateway_name) > 0 else '')
	for k in ['username', 'password', 'gateway_url']:
		v = conf.get_value(k).strip()
		pfmt = pfmt.replace('<{0}>'.format(k), v + '\\n' if len(v) > 0 else '')
	pfmt = pfmt.replace('<saml_username>', saml_username + '\\n')
	if rmnl and pfmt.endswith('\\n'):
		pfmt = pfmt[:-2]
	pcmd = 'printf \'{0}\''.format(pfmt)

	print()
	if conf.get_bool('execute'):
		ecmd = [os.path.expandvars(os.path.expanduser(x)) for x in shlex.split(cmd)]
		pp = subprocess.Popen(shlex.split(pcmd), stdout=subprocess.PIPE)
		cp = subprocess.Popen(ecmd, stdin=pp.stdout, stdout=sys.stdout)
		if pp.stdout is not None:
			pp.stdout.close()
		# Do not abort on SIGINT. openconnect will perform proper exit & cleanup
		signal.signal(signal.SIGINT, signal.SIG_IGN)
		cp.communicate()
	else:
		print('{0} | {1}'.format(pcmd, cmd))
	return 0


if __name__ == '__main__':
	sys.exit(main())
