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
import argparse, base64, getpass, io, os, re, shlex, signal, subprocess, sys, tempfile, time, traceback
import requests
from lxml import etree

if sys.version_info >= (3,):
	from urllib.parse import urlparse, urljoin  # pylint: disable=import-error
	text_type = str
	binary_type = bytes
else:
	from urlparse import urlparse, urljoin  # pylint: disable=import-error
	text_type = unicode  # pylint: disable=undefined-variable
	binary_type = str
	input = raw_input  # pylint: disable=undefined-variable,redefined-builtin

try:
	# pylint: disable=unused-import
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

quiet = False

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
				dbg(True, name, '{0}.decoded: {1}'.format(k, saml_raw))
			except Exception:
				pass


def err(s):
	# type: (str) -> NoReturn
	print('[ERROR] {0}'.format(s), file=sys.stderr)
	sys.exit(1)

def _remx(c, v): return re.search(r'\s*' + v + r'\s*"?[=:]\s*(?:"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\')', c)
_refx = lambda mx: to_b(mx.group(1) if mx.group(1) is not None else mx.group(2)).decode('unicode_escape').strip()

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

def parse_form(html, current_url=None):
	# type: (etree._Element, Optional[str]) -> Tuple[str, Dict[str, str]]
	xform = html.find('.//form')
	url = xform.attrib.get('action', '').strip()
	if not url.startswith('http') and current_url:
		url = urljoin(current_url, url)
	data = {}
	for xinput in html.findall('.//input'):
		k = xinput.attrib.get('name', '').strip()
		v = xinput.attrib.get('value', '').strip()
		if k and v:
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
		self._ocerts = False

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
		s.cert = None
		if name == 'okta':
			if self.okta_cli_cert:
				s.cert = self.okta_cli_cert
		elif self.vpn_cli_cert:
			s.cert = self.vpn_cli_cert
		return s

	def get_value(self, name):
		# type: (str) -> str
		return to_n(getattr(self, name))

	def get_bool(self, name):
		# type: (str) -> bool
		v = self.get_value(name)
		return v.lower() in ['1', 'true']

	def add_cert(self, cert, name='unknown'):
		# type: (str, str) -> None
		if not cert:
			return
		if name in ['vpn_cli', 'okta_cli', 'okta_url']:
			return
		if name != 'vpn_url':
			self._ocerts = True
		if not self.certs:
			if 'certs' in self._store:
				self.certs_fh = io.open(self._store['certs'], 'wb')
			else:
				self.certs_fh = tempfile.NamedTemporaryFile(prefix='gpvpn_', delete=False)
				log('using temporary file {0} for storing certificates'.format(self.certs_fh.name))
			self.certs = self.certs_fh.name
		self.certs_fh.write(to_b(cert))
		self.certs_fh.flush()

	def get_verify(self, name, default_verify=True):
		# type: (str, bool) -> Union[str, bool]
		name = name.lower()
		if name not in ['okta', 'portal', 'gateway']:
			raise Exception('unknonw verify request: {0}'.format(name))
		if name == 'okta' and 'okta_url_cert' in self._store:
			return self._store['okta_url_cert']
		if name == 'portal' and 'vpn_url_cert' in self._store:
			return self._store['vpn_url_cert']
		if name == 'gateway' and self._ocerts:
			return self.certs
		return default_verify

	def get_line(self, name):
		# type: (str) -> int
		if name in self._lines:
			return self._lines[name]
		return 0

	# pylint: disable=protected-access
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
				if not k:
					continue
				conf._store[k] = v.strip()
		if not conf._store.get('username', '').strip():
			conf._store['username'] = input('username: ').strip()
		if not conf._store.get('password', '').strip():
			conf._store['password'] = getpass.getpass('password: ').strip()
		for k in conf._store:
			if not k.endswith('_cert'):
				continue
			cert_name = k[:-5]
			cert_file = conf._store.get(k, '').strip()
			if cert_file:
				cert_file = os.path.expandvars(os.path.expanduser(cert_file))
				if not os.path.exists(cert_file):
					err('configured "{0}" file "{1}" does not exist'.format(k, cert_file))
				with io.open(cert_file, 'rb') as fp:
					conf.add_cert(fp.read(), cert_name)
		for k in keys:
			if k not in conf._store:
				err('missing configuration key: {0}'.format(k))
			else:
				if not conf._store[k].strip():
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
	mfa_order = (conf.mfa_order or 'totp sms push webauthn').split()
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
	elif not value:
		priority += (128 - line_nr)
	else:
		priority += (512 - line_nr)
	return priority


def get_state_token(conf, c):
	# type: (Conf, str) -> Optional[str]
	rx_state_token = _remx(c, 'stateToken')
	if not rx_state_token:
		dbg(conf.debug, 'not found', 'stateToken')
		return None
	return _refx(rx_state_token)

def get_redirect_url(conf, c, current_url=None):
	# type: (Conf, str, Optional[str]) -> Optional[str]
	rx_redirect_url = _remx(c, 'redirectUri')
	if rx_redirect_url:
		redirect_uri = _refx(rx_redirect_url)
		if redirect_uri.startswith('http'):
			return redirect_uri
	rx_base_url = _remx(c, 'baseUrl')
	rx_from_uri = _remx(c, 'fromUri')
	if not rx_from_uri:
		dbg(conf.debug, 'not found', 'fromUri')
		return None
	from_uri = _refx(rx_from_uri)
	if from_uri.startswith('http'):
		return from_uri
	if not rx_base_url:
		dbg(conf.debug, 'not found', 'baseUri')
		if current_url:
			return urljoin(current_url, from_uri)
		return from_uri
	base_url = _refx(rx_base_url)
	return base_url + from_uri

def parse_url(url):
	# type: (str) -> Tuple[str, str]
	purl = list(urlparse(url))
	return (purl[0], purl[1].split(':')[0])

def _send_req_pre(conf, name, url, data, expected_url=None, v=True):
	# type: (Conf, str, str, Dict[str, Any], Optional[str], Union[str, bool]) -> None
	dbg(conf.debug, '{0}.request'.format(name), '{0}, verify:{1}'.format(url, v))
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

def send_req(conf, dest, name, url, data, get=False, expected_url=None, can_fail=False):
	# type: (Conf, str, str, str, Dict[str, Any], bool, Optional[str], bool) -> Tuple[int, requests.structures.CaseInsensitiveDict[str], str]
	v = conf.get_verify(dest)
	_send_req_pre(conf, name, url, data, expected_url, v)
	s = conf.get_session(dest)
	if get:
		r = s.get(url, verify=v)
	else:
		r = s.post(url, data=data, verify=v)
	_send_req_post(conf, r, name, can_fail)
	return r.status_code, r.headers, r.text

def send_json_req(conf, dest, name, url, data, get=False, expected_url=None, can_fail=False):
	# type: (Conf, str, str, str, Dict[str, Any], bool, Optional[str], bool) -> Tuple[int, requests.structures.CaseInsensitiveDict[str], Dict[str, Any]]
	v = conf.get_verify(dest)
	_send_req_pre(conf, name, url, data, expected_url, v)
	headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
	s = conf.get_session(dest)
	if get:
		r = s.get(url, headers=headers, verify=v)
	else:
		r = s.post(url, headers=headers, json=data, verify=v)
	_send_req_post(conf, r, name, can_fail)
	return r.status_code, r.headers, parse_rjson(r)

def paloalto_prelogin(conf, gateway_url=None):
	# type: (Conf, Optional[str]) -> etree._Element
	dest = 'portal'
	if gateway_url:
		# 2nd round or direct gateway: use gateway
		log('prelogin request [gateway_url]')
		dest = 'gateway'
		url = '{0}/ssl-vpn/prelogin.esp'.format(gateway_url)
	else:
		# 1st round: use portal
		log('prelogin request [vpn_url]')
		url = '{0}/global-protect/prelogin.esp'.format(conf.vpn_url)
	_, _h, c = send_req(conf, dest, 'prelogin', url, {}, get=True)
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
	if not saml_req.text.strip():
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
	_, _h, c = send_req(conf, 'okta', 'saml', url, data, expected_url=conf.okta_url)
	redirect_url = get_redirect_url(conf, c, url)
	if redirect_url is None:
		err('did not find redirect url')
	return c, redirect_url

def okta_auth(conf, stateToken=None):
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
	_, _h, j = send_json_req(conf, 'okta', 'auth', url, data)
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
		if not url:
			err('skip url not found')
		state_token = j.get('stateToken', '').strip()
		if not state_token:
			err('empty state token')
		data = {'stateToken': state_token}
		_, _h, j = send_json_req(conf, 'okta', 'skip', url, data, expected_url=conf.okta_url)
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
	if status != 'success':
		print(j)
		err('unknown status: {0}'.format(status))
	session_token = j.get('sessionToken', '').strip()
	if not session_token:
		err('empty session token')
	return True, session_token

def okta_mfa(conf, j):
	# type: (Conf, Dict[str, Any]) -> Dict[str, Any]
	state_token = j.get('stateToken', '').strip()
	if not state_token:
		err('empty state token')
	factors_json = j.get('_embedded', {}).get('factors', [])
	if not factors_json:
		err('no factors found')
	factors = []
	for factor in factors_json:
		factor_id = factor.get('id', '').strip()
		factor_type = factor.get('factorType', '').strip().lower()
		provider = factor.get('provider', '').strip().lower()
		factor_url = factor.get('_links', {}).get('verify', {}).get('href')
		if not factor_type or not provider or not factor_url:
			continue
		factors.append({
			'id': factor_id,
			'type': factor_type,
			'provider': provider,
			'priority': mfa_priority(conf, factor_type, provider),
			'url': factor_url})
	dbg(conf.debug, 'factors', *factors)
	if not factors:
		err('no factors found')
	r = None # type: Optional[Dict[str, Any]]
	for f in sorted(factors, key=lambda x: x.get('priority', 0), reverse=True):
		ftype = f.get('type')
		fprovider = f.get('provider')
		if ftype == 'token:software:totp' or (ftype, fprovider) == ('token', 'symantec'):
			r = okta_mfa_totp(conf, f, state_token)
		elif ftype == 'sms':
			r = okta_mfa_sms(conf, f, state_token)
		elif ftype == 'push':
			r = okta_mfa_push(conf, f, state_token)
		elif ftype == 'webauthn':
			r = okta_mfa_webauthn(conf, f, state_token)
		if r is not None:
			break
	if r is None:
		err('no factors processed')
	return r

def okta_mfa_totp(conf, factor, state_token):
	# type: (Conf, Dict[str, str], str) -> Optional[Dict[str, Any]]
	provider = factor.get('provider', '')
	secret = conf.get_value('totp.{0}'.format(provider))
	code = None
	if not secret:
		code = input('{0} TOTP: '.format(provider)).strip()
	else:
		if not have_pyotp:
			err('Need pyotp package, consider doing \'pip install pyotp\' (or similar)')
		totp = pyotp.TOTP(secret)
		code = totp.now()
	code = code or ''
	if not code:
		return None
	data = {
		'factorId': factor.get('id'),
		'stateToken': state_token,
		'passCode': code
	}
	log('mfa {0} totp request: {1} [okta_url]'.format(provider, code))
	_, _h, j = send_json_req(conf, 'okta', 'totp mfa', factor.get('url', ''), data, expected_url=conf.okta_url)
	return j

def okta_mfa_sms(conf, factor, state_token):
	# type: (Conf, Dict[str, str], str) -> Optional[Dict[str, Any]]
	provider = factor.get('provider', '')
	data = {
		'factorId': factor.get('id'),
		'stateToken': state_token
	}
	log('mfa {0} sms request [okta_url]'.format(provider))
	_, _h, j = send_json_req(conf, 'okta', 'sms mfa (1)', factor.get('url', ''), data, expected_url=conf.okta_url)
	code = input('{0} SMS verification code: '.format(provider)).strip()
	if not code:
		return None
	data['passCode'] = code
	log('mfa {0} sms request [okta_url]'.format(provider))
	_, _h, j = send_json_req(conf, 'okta', 'sms mfa (2)', factor.get('url', ''), data, expected_url=conf.okta_url)
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
		_, _h, j = send_json_req(conf, 'okta', 'push mfa ({0})'.format(counter), factor.get('url', ''), data, expected_url=conf.okta_url)
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
	_, _h, j = send_json_req(conf, 'okta', 'webauthn mfa challenge', factor.get('url', ''), data, expected_url=conf.okta_url)
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
	_, _h, j = send_json_req(conf, 'okta', 'uf2 mfa signature', j['_links']['next']['href'], data, expected_url=conf.okta_url)
	return j

def okta_redirect(conf, session_token, redirect_url, gateway_url=None):
	# type: (Conf, str, str, Optional[str]) -> Tuple[str, str]
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
			_, h, c = send_req(conf, 'okta', 'redirect', url, data)
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
			if gateway_url:
				log('okta redirect form request [gateway]')
				dest = 'gateway'
				expected_url = gateway_url # type: Optional[str]
			else:
				log('okta redirect form request [vpn_url]')
				dest = 'portal'
				expected_url = conf.vpn_url
				purl, pexp = parse_url(form_url), parse_url(expected_url)
				if purl != pexp:
					# NOTE: redirect to nearest (geo) portal without any prior knowledge
					warn('{0}: unexpected url found {1} != {2}'.format('redirect form', purl, pexp))
					expected_url = None
			_, h, c = send_req(conf, dest, 'redirect form', form_url, form_data, expected_url=expected_url)
		saml_username = h.get('saml-username', '').strip()
		prelogin_cookie = h.get('prelogin-cookie', '').strip()
		if saml_username and prelogin_cookie:
			saml_auth_status = h.get('saml-auth-status', '').strip()
			saml_slo = h.get('saml-slo', '').strip()
			dbg(conf.debug, 'saml prop', [saml_auth_status, saml_slo])
			return saml_username, prelogin_cookie

def paloalto_getconfig(conf, username=None, prelogin_cookie=None, can_fail=False):
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
	sc, _h, c = send_req(conf, 'portal', 'getconfig', url, data, can_fail=can_fail)
	if sc != 200:
		return sc, '', {}
	x = parse_xml(c)
	xtmp = x.find('.//portal-userauthcookie')
	if xtmp is None:
		err('did not find portal-userauthcookie')
	portal_userauthcookie = xtmp.text
	if not portal_userauthcookie:
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
			conf.add_cert(cert, 'getconfig')
	return 200, portal_userauthcookie, gateways

# Combined first half of okta_saml with second half of okta_redirect
def okta_saml_2(conf, gateway_url, saml_xml):
	# type: (Conf, str, str) -> Tuple[str, str]
	log('okta saml request (2) [okta_url]')
	url, data = parse_form(saml_xml)
	dbg_form(conf, 'okta.saml request(2)', data)
	_, h, c = send_req(conf, 'okta', 'okta saml request (2)', url, data, expected_url=conf.okta_url)
	xhtml = parse_html(c)
	url, data = parse_form(xhtml)
	dbg_form(conf, 'okta.saml request(2)', data)
	log('okta redirect form request (2) [gateway]')
	_, h, c = send_req(conf, 'gateway', 'okta redirect form (2)', url, data, expected_url=gateway_url)
	saml_username = h.get('saml-username', '').strip()
	if not saml_username:
		err('saml-username empty')
	prelogin_cookie = h.get('prelogin-cookie', '').strip()
	if not prelogin_cookie:
		err('prelogin-cookie empty')
	return saml_username, prelogin_cookie

def okta_oie_parse_response(conf, j):
	state_handle = j.get('stateHandle')
	dbg(conf.debug, 'stateHandle: {0}'.format(state_handle))
	if not state_handle:
		err('missing stateHandle in response')
	rem = j.get('remediation')
	if not rem:
		err('no remediation in response')
	if rem.get('type') != 'array':
		err('remediation in response is not array')
	return state_handle, rem

def okta_oie_response_lookup(j, sk, k, v):
	for sj in j.get(sk, []):
		if sj.get(k) == v:
			return sj
	err('no "{0}" found as "{1}" in "{2}" items'.format(v, k, sk))

def okta_oie_mfa_password(conf, state_handle, mfa, rem):
	rem_ca = okta_oie_response_lookup(rem, 'value', 'name', 'challenge-authenticator')
	log('mfa password request')
	data = {'stateHandle': state_handle, 'credentials':{'passcode': conf.password}}
	url = '{0}/idp/idx/challenge/answer'.format(conf.okta_url)
	_, h, j = send_json_req(conf, 'okta', 'idp/idx/challenge/answer', url, data)
	return okta_oie_identify_parse(conf, state_handle, j)

def okta_oie_mfa_totp(conf, state_handle, mfa, rem):
	rem_ca = okta_oie_response_lookup(rem, 'value', 'name', 'challenge-authenticator')
	provider = mfa.get('provider', '')
	secret = conf.get_value('totp.{0}'.format(provider))
	code = None
	if not secret:
		code = input('{0} TOTP: '.format(provider)).strip()
	else:
		if not have_pyotp:
			err('Need pyotp package, consider doing \'pip install pyotp\' (or similar)')
		totp = pyotp.TOTP(secret)
		code = totp.now()
	code = code or ''
	if not code:
		return None
	log('mfa {0} totp request: {1} [okta_url]'.format(mfa.get('provider'), code))
	data = {'stateHandle': state_handle, 'credentials':{'passcode': code}}
	url = '{0}/idp/idx/challenge/answer'.format(conf.okta_url)
	_, h, j = send_json_req(conf, 'okta', 'idp/idx/challenge/answer', url, data)
	return okta_oie_identify_parse(conf, state_handle, j)

def okta_oie_mfa_push(conf, state_handle, mfa, rem):
	rem_cp = okta_oie_response_lookup(rem, 'value', 'name', 'challenge-poll')
	c = 0
	while True:
		if c > 10:
			err('waiting for push notification too long')
		log('mfa poll for push notification [okta_url]')
		data = {'stateHandle': state_handle}
		url = '{0}/idp/idx/authenticators/poll'.format(conf.okta_url)
		_, h, j = send_json_req(conf, 'okta', 'idp/idx/authenticators/poll', url, data)
		state_handle = j.get('stateHandle')
		success = j.get('success')
		if success:
			return success.get('href')
		time.sleep(4)
		c += 1

def okta_oie_mfa_sms(conf, state_handle, mfa, rem):
	rem_ca = okta_oie_response_lookup(rem, 'value', 'name', 'challenge-authenticator')
	code = input('SMS verification code: ').strip()
	log('mfa sms request: {0} [okta_url]'.format(code))
	data = {'stateHandle': state_handle, 'credentials':{'passcode': code}}
	url = '{0}/idp/idx/challenge/answer'.format(conf.okta_url)
	_, h, j = send_json_req(conf, 'okta', 'idp/idx/challenge/answer', url, data)
	return okta_oie_identify_parse(conf, state_handle, j)

def okta_oie_login(conf, state_handle):
	url = '{0}/idp/idx/introspect'.format(conf.okta_url)
	data = {'stateToken': state_handle}
	_, h, j = send_json_req(conf, 'okta', 'idp/idx/introspect', url, data)
	rem = j.get('remediation')
	if not rem:
		err('no remediation in response')
	remv = rem.get('value')
	if not remv:
		err('no remediation value in response')
	rem_identify = None
	for ji in remv:
		if ji.get('name') == 'identify':
			rem_identify = ji
			break
	if not rem_identify:
		err('no identify remediation in response')
	riv = rem_identify.get('value')
	if not riv:
		err('no identify remediation value in response')
	rif = []
	for ji in riv:
		if ji.get('required'):
			fn = ji.get('name')
			if not fn:
				continue
			rif.append(fn)
	data = {'stateHandle': state_handle, 'identifier': conf.username, 'credentials': {'passcode': conf.password}}
	for fn in list(data.keys()):
		if not fn in rif:
			del data[fn]
	url = '{0}/idp/idx/identify'.format(conf.okta_url)
	_, h, j = send_json_req(conf, 'okta', 'idp/idx/identify', url, data)
	return okta_oie_identify_parse(conf, state_handle, j)

def okta_oie_identify_parse(conf, state_handle, j):
	success = j.get('success')
	if success:
		rurl = success.get('href')
		return rurl
	state_handle, rem = okta_oie_parse_response(conf, j)
	rem_saa = okta_oie_response_lookup(rem, 'value', 'name', 'select-authenticator-authenticate')
	rem_saa_a = okta_oie_response_lookup(rem_saa, 'value', 'name', 'authenticator')

	mfas = []
	for aopt in rem_saa_a.get('options'):
		label = aopt.get('label', '').strip()
		if not label:
			continue

		aopt_form = aopt.get('value', {'form':{}}).get('form')
		mfa_id, mfa_eid = None, None
		for fi in aopt_form.get('value'):
			fi_name = fi.get('name', '')
			if not fi_name or fi_name == 'methodType':
				continue
			fi_req = fi.get('required', False)
			if fi_req:
				if fi_name == 'id':
					mfa_id = fi.get('value')
				elif fi_name == 'enrollmentId':
					mfa_eid = fi.get('value')
				else:
					err('unknown mfa required field: {0}'.format(fi_name))
		aopt_mto = aopt_idv = amt = okta_oie_response_lookup(aopt_form, 'value', 'name', 'methodType')
		mfa_mts = []
		if aopt_mto.get('value'):
				mfa_mts.append(aopt_mto.get('value'))
		else:
			for mto in aopt_mto.get('options', []):
				mt = mto.get('value')
				if not mt:
					continue
				mfa_mts.append(mt)
		for mt in mfa_mts:
			mfa_type = mt
			if mfa_type == 'otp':
				mfa_type = 'totp'
			mfa_provider = ''
			if 'Google' in label:
				mfa_provider = 'google'
			if 'Okta' in label:
				mfa_provider = 'okta'
			priority = mfa_priority(conf, mfa_type, mfa_provider)
			log('available mfa: {0} ({1})'.format(label, mt))
			mfas.append({'name': label, 'id':mfa_id, 'eid': mfa_eid, 'provider': mfa_provider, 'type': mt, 'priority': priority})
	if len(mfas) == 0:
		err('no mfa found')
	r = None # type: Optional[Dict[str, Any]]
	for mfa in sorted(mfas, key=lambda x: x.get('priority', 0), reverse=True):
		log('using mfa: {0}'.format(mfa.get('name')))
		data = {'stateHandle': state_handle, 'authenticator':{'id': mfa.get('id'), 'methodType': mfa.get('type')}}
		if mfa.get('eid'):
			data['authenticator']['enrollmentId'] = mfa.get('eid')
		url = '{0}/idp/idx/challenge'.format(conf.okta_url)
		_, h, j = send_json_req(conf, 'okta', 'idp/idx/challenge', url, data)
		state_handle, rem = okta_oie_parse_response(conf, j)
		mtype = mfa.get('type')
		if mtype == 'password':
			r = okta_oie_mfa_password(conf, state_handle, mfa, rem)
		elif mtype == 'otp' or mtype == 'totp':
			r = okta_oie_mfa_totp(conf, state_handle, mfa, rem)
		elif mtype == 'sms':
			r = okta_oie_mfa_sms(conf, state_handle, mfa, rem)
		elif mtype == 'push':
			r = okta_oie_mfa_push(conf, state_handle, mfa, rem)
		#elif mtype == 'webauthn':
		#   TODO
		if r is not None:
			break
	if r is None:
		err('no mfa processed')
	return r

def okta_oie(conf, state_token, gw_url):
	# type: (Conf, str) -> Tuple[str, str]
	if not state_token:
		return None, None
	url = '{0}/idp/idx/introspect'.format(conf.okta_url)
	data = {'stateToken': state_token}
	_, h, j = send_json_req(conf, 'okta', 'idp/idx/introspect', url, data)
	state_handle, rem = okta_oie_parse_response(conf, j)

	rurl = okta_oie_login(conf, state_handle)
	_, h, c = send_req(conf, 'okta', 'redirect', rurl, {}, get=True)
	xhtml = parse_html(c)
	form_url, form_data = parse_form(xhtml, url)
	dbg_form(conf, 'okta.redirect request', data)

	if gw_url:
		log('okta redirect form request [gateway]')
		dest = 'gateway'
		expected_url = gw_url # type: Optional[str]
	else:
		log('okta redirect form request [vpn_url]')
		dest = 'portal'
		expected_url = conf.vpn_url
		purl, pexp = parse_url(form_url), parse_url(expected_url)
		if purl != pexp:
			# NOTE: redirect to nearest (geo) portal without any prior knowledge
			warn('{0}: unexpected url found {1} != {2}'.format('redirect form', purl, pexp))
			expected_url = None
	_, h, c = send_req(conf, dest, 'redirect form', form_url, form_data, expected_url=expected_url)
	saml_username = h.get('saml-username', '').strip()
	prelogin_cookie = h.get('prelogin-cookie', '').strip()
	if saml_username and prelogin_cookie:
		saml_auth_status = h.get('saml-auth-status', '').strip()
		saml_slo = h.get('saml-slo', '').strip()
		dbg(conf.debug, 'saml prop', [saml_auth_status, saml_slo])
		return saml_username, prelogin_cookie
	return None, None

def output_gateways(gateways):
	# type: (Dict[str, str]) -> None
	print("Gateways:")
	for k in sorted(gateways.keys()):
		print("\t{0} {1}".format(k, gateways[k]))

def choose_gateway_url(conf, gateways):
	# type: (Conf, Dict[str, str]) -> str
	if conf.gateway_url:
		return conf.gateway_url
	if not gateways:
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

def run_openconnect(conf, do_portal_auth, urls, saml_username, cookies):
	# type: (Conf, bool, Dict[str, str], str, Dict[str, str]) -> int
	if do_portal_auth:
	    url = urls.get('portal')
	    cookie_type = 'portal:portal-userauthcookie'
	    cookie = cookies.get('userauthcookie')
	else:
	    url = urls.get('gateway')
	    cookie_type = 'gateway:prelogin-cookie'
	    cookie = cookies.get('prelogin-cookie')
	if cookie is None or cookie == 'empty':
		err('empty "{0}" cookie'.format(cookie_type))

	cmd = conf.openconnect_cmd or 'openconnect'
	cmd += ' --protocol=gp -u \'{0}\''.format(saml_username)
	if do_portal_auth and conf.gateway:
		cmd += ' --authgroup=\'{0}\''.format(conf.gateway)
	cmd += ' --usergroup {0}'.format(cookie_type)
	if conf.vpn_cli_cert:
		cmd += ' --certificate=\'{0}\''.format(conf.vpn_cli_cert)
	if conf.certs:
		cmd += ' --cafile=\'{0}\''.format(conf.certs)
	cmd += ' --passwd-on-stdin ' + conf.openconnect_args + ' \'{0}\''.format(url)

	pfmt = conf.openconnect_fmt
	if not pfmt:
		pfmt = '<cookie><cookie>' if do_portal_auth else '<cookie>'
	rmnl = pfmt.endswith('>')
	pfmt = pfmt.replace('<cookie>', cookie + '\\n')
	for k in ['username', 'password', 'gateway', 'gateway_url']:
		v = conf.get_value(k).strip()
		pfmt = pfmt.replace('<{0}>'.format(k), v + '\\n' if v else '')
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
		if conf.certs:
			try:
				os.unlink(conf.certs)
			except Exception:
				pass
	else:
		if conf.certs:
			cmd += '; rm -f \'{0}\''.format(conf.certs)
		print('{0} | {1}'.format(pcmd, cmd))
	return 0

def parse_args():
	# type: () -> argparse.Namespace
	parser = argparse.ArgumentParser(description="""
	This is an OpenConnect wrapper script that automates connecting
	to PaloAlto Networks GlobalProtect VPN using Okta 2FA.""")

	parser.add_argument('conf_file', help='e.g. ~/.config/gp-okta.conf')
	parser.add_argument('-l', '--list-gateways', default=False, action='store_true', help='get list of gateways from portal')
	parser.add_argument('-d', '--gpg-decrypt', action='store_true', help='decrypt configuration file with gpg')
	parser.add_argument('--gpg-home', default=os.path.expanduser('~/.gnupg'), help='path to gpg home directory')
	parser.add_argument('-q', '--quiet', default=False, action='store_true', help='disable verbose logging')
	args = parser.parse_args()
	return args

def read_conf(fp, gpg_decrypt, gpg_home):
	# type: (str, bool, str) -> str
	if not os.path.exists(fp):
		err('config file "{0}" does not exist'.format(fp))
	cc = ''
	with io.open(fp, 'rb') as fh:
		cc = fh.read()
	if fp.lower().endswith('.gpg') and not gpg_decrypt:
		gpg_decrypt = True
		log('conf file looks like gpg encrypted. trying decryption')
	if gpg_decrypt:
		if not os.path.isdir(gpg_home):
			err('invalid gpg home directory: "{0}"'.format(gpg_home))
		if not have_gnupg:
			err('Need gnupg package for reading gnupg encrypted files. Consider doing `pip install python-gnupg` (or similar)')
		gpg = gnupg.GPG(gnupghome=gpg_home)
		dc = gpg.decrypt(cc)
		if not dc.ok:
			err('failed to decrypt config file. status: {0}, error:\n {1}'.format(dc.status, dc.stderr))
		cc = dc.data
	return cc

def main():
	# type: () -> int
	args = parse_args()

	global quiet
	quiet = args.quiet


	conf_data = read_conf(args.conf_file, args.gpg_decrypt, args.gpg_home)
	conf = Conf.from_data(conf_data)

	if args.list_gateways:
		log('listing gateways')
		sc, _, gateways = paloalto_getconfig(conf, can_fail=True)
		if sc == 200:
			output_gateways(gateways)
			return 0
		log('gateway list requires authentication')

	another_dance = conf.get_bool('another_dance')
	gateway_url = conf.gateway_url
	do_portal_login = another_dance or not gateway_url
	do_portal_auth = not gateway_url

	if do_portal_login or args.list_gateways:
		saml_xml = paloalto_prelogin(conf)
	else:
		saml_xml = paloalto_prelogin(conf, gateway_url)

	rsaml, redirect_url = okta_saml(conf, saml_xml)
	oie = conf.get_bool('okta_oie') if conf.okta_oie.strip() != '' else True
	if oie:
		state_token = get_state_token(conf, rsaml)
		dbg(conf.debug, 'stateToken: {0}'.format(state_token))
		gw_url = gateway_url if do_portal_login else None
		saml_username, prelogin_cookie = okta_oie(conf, state_token, gw_url)
	else:
		token = okta_auth(conf)
		log('sessionToken: {0}'.format(token))
		if do_portal_login:
			saml_username, prelogin_cookie = okta_redirect(conf, token, redirect_url)
		else:
			saml_username, prelogin_cookie = okta_redirect(conf, token, redirect_url, gateway_url)

	userauthcookie = None
	if do_portal_login or args.list_gateways:
		if args.list_gateways:
			log('listing gateways')
		sc, userauthcookie, gateways = paloalto_getconfig(conf, saml_username, prelogin_cookie, can_fail=args.list_gateways)
		if args.list_gateways:
			if sc == 200:
				output_gateways(gateways)
				return 0
			err('could not list gateways')
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
		do_portal_auth = False

	return run_openconnect(
		conf, do_portal_auth,
		{'portal': conf.vpn_url, 'gateway': gateway_url},
		saml_username,
		{'userauthcookie': userauthcookie or '', 'prelogin-cookie': prelogin_cookie})


if __name__ == '__main__':
	sys.exit(main())
