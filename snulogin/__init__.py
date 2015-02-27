# -*- coding: utf-8 -*-

import requests
from bs4 import BeautifulSoup

import ssl
from ssl import match_hostname
import logging
import socket

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
from requests.packages.urllib3.connectionpool import HTTPConnectionPool
from requests.packages.urllib3.connectionpool import HTTPSConnectionPool
from requests.packages.urllib3.util import get_host

from http.client import HTTPSConnection
log = logging.getLogger(__name__)


def connection_from_url(url, **kw):
    """
    Given a url, return an :class:`.ConnectionPool` instance of its host.

    This is a shortcut for not having to parse out the scheme, host, and port
    of the url before creating an :class:`.ConnectionPool` instance.

    :param url:
        Absolute URL string that must include the scheme. Port is optional.

    :param \**kw:
        Passes additional parameters to the constructor of the appropriate
        :class:`.ConnectionPool`. Useful for specifying things like
        timeout, maxsize, headers, etc.

    Example: ::

        >>> conn = connection_from_url('http://google.com/')
        >>> r = conn.request('GET', '/')
    """
    scheme, host, port = get_host(url)
    if scheme == 'https':
        return MyHTTPSConnectionPool(host, port=port, **kw)
    else:
        return HTTPConnectionPool(host, port=port, **kw)


class MyHTTPSConnectionPool(HTTPSConnectionPool):
    def __init__(self, host, port=None,
                 strict=False, timeout=None, maxsize=1,
                 block=False, headers=None,
                 key_file=None, cert_file=None,
                 cert_reqs='CERT_REQUIRED',
                 ca_certs='/etc/ssl/certs/ca-certificates.crt',
                 ssl_version=ssl.PROTOCOL_SSLv23, ciphers=None):

        super(HTTPSConnectionPool, self).__init__(host, port,
                                                  strict, timeout, maxsize,
                                                  block, headers)
        self.key_file = key_file
        self.cert_file = cert_file
        self.cert_reqs = cert_reqs
        self.ca_certs = ca_certs
        self.ssl_version = ssl_version
        self.ciphers = ciphers

    def _new_conn(self):
        """
        Return a fresh :class:`httplib.HTTPSConnection`.
        """
        self.num_connections += 1
        log.info("Starting new HTTPS connection (%d): %s"
                 % (self.num_connections, self.host))

        connection = MyVerifiedHTTPSConnection(host=self.host, port=self.port)
        connection.set_cert(key_file=self.key_file, cert_file=self.cert_file,
                            cert_reqs=self.cert_reqs, ca_certs=self.ca_certs)
        connection.set_ssl_version(self.ssl_version)
        connection.set_ciphers(self.ciphers)
        return connection


class MyVerifiedHTTPSConnection(HTTPSConnection):
    """
    Based on httplib.HTTPSConnection but wraps the socket with
    SSL certification.
    """
    cert_reqs = None
    ca_certs = None
    client_cipher = None

    def set_cert(self, key_file=None, cert_file=None,
                 cert_reqs='CERT_NONE', ca_certs=None):
        ssl_req_scheme = {
            'CERT_NONE': ssl.CERT_NONE,
            'CERT_OPTIONAL': ssl.CERT_OPTIONAL,
            'CERT_REQUIRED': ssl.CERT_REQUIRED
        }

        self.key_file = key_file
        self.cert_file = cert_file
        self.cert_reqs = ssl_req_scheme.get(cert_reqs) or ssl.CERT_NONE
        self.ca_certs = ca_certs

    def set_ssl_version(self, ssl_version=ssl.PROTOCOL_SSLv23):
        self.ssl_version = ssl_version

    def set_ciphers(self, ciphers=None):
        self.ciphers = ciphers

    def connect(self):
        # Add certificate verification
        sock = socket.create_connection((self.host, self.port), self.timeout)

        # Wrap socket using verification with the root certs in
        # trusted_root_certs
        self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file,
                                    cert_reqs=self.cert_reqs,
                                    ca_certs=self.ca_certs,
                                    ssl_version=self.ssl_version,
                                    ciphers=self.ciphers)
        if self.ca_certs:
            match_hostname(self.sock.getpeercert(), self.host)

        self.is_verified = (self.cert_reqs == ssl.CERT_REQUIRED
                            or self.assert_fingerprint is not None)

    def close(self):
        if self.sock:
            self.client_cipher = self.sock.cipher()
        HTTPSConnection.close(self)


class SSLAdapter(HTTPAdapter):
    '''An HTTPS Transport Adapter that uses an arbitrary SSL version.'''
    def __init__(self, ssl_version=None, **kwargs):
        self.ssl_version = ssl_version

        super(SSLAdapter, self).__init__(**kwargs)

    def get_connection(self, url, proxies=None):
        """Returns a connection for the given URL."""

        # proxies are not supported
        return connection_from_url(url)

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=self.ssl_version)

    def cert_verify(self, conn, url, verify, cert):
        # I'm overloading the content of verify since this API is so
        # braindead. If verify is a dict then key 'verify' represents the
        # original meaning, the other keys are my own.
        if isinstance(verify, bool):
            super(SSLAdapter, self).cert_verify(conn, url, verify, cert)
        elif isinstance(verify, dict):
            if 'verify' in verify:
                super(SSLAdapter, self).cert_verify(conn, url,
                                                    verify['verify'], cert)
            if 'ssl_version' in verify:
                conn.ssl_version = verify['ssl_version']
            if 'ciphers' in verify:
                conn.ciphers = verify['ciphers']
            if 'cert_file' in verify:
                conn.cert_file = verify['cert_file']
            if 'key_file' in verify:
                conn.key_file = verify['key_file']
        else:
            pass


def login(userid, password):
    """Login to sso.snu.ac.kr.

    If login process execute successfully, you will get session object with auth
    cookies for sso.snu.ac.kr.

    :param userid: userid
    :param password: password

    Example: ::

        >>> sess = snulogin.login('myuserid', 'mypassword')
        >>> r = sess.get('https://my.snu.ac.kr/')
    """
    s = requests.Session()
    s.mount('https://', SSLAdapter(ssl.PROTOCOL_TLSv1))

    r = s.get('http://sso.snu.ac.kr/snu/ssologin.jsp')
    url = ('https' + r.url[4:]).replace('loginFormPage', 'idPasswordLogin')
    data = {
        'userid': userid,
        'password': password,
        'id_save': 'on',
        'btn_login.x': '45',
        'btn_login.y': '10'
    }
    r = s.post(url, data=data, verify={'verify': True, 'ciphers': 'RC4-MD5'})
    soup = BeautifulSoup(r.text)
    data = {}
    for ele in soup.find('form').find_all('input'):
        data[ele['name']] = ele['value']
    r = s.post(
        'https://sso.snu.ac.kr/nls3/fcs',
        data=data,
        verify={'verify': True, 'ciphers': 'RC4-MD5'}
    )
    return s
