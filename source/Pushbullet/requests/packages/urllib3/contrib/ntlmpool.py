# urllib3/contrib/ntlmpool.py
# Copyright 2008-2013 Andrey Petrov and contributors (see CONTRIBUTORS.txt)
#
# This module is part of urllib3 and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php

"""
NTLM authenticating pool, contributed by erikcederstran

Issue #10, see: http://code.google.com/p/urllib3/issues/detail?id=10
"""

try:
    from http.client import HTTPSConnection
except ImportError:
    from httplib import HTTPSConnection
from logging import getLogger
from ntlm import ntlm

from urllib3 import HTTPSConnectionPool


log = getLogger(__name__)


class NTLMConnectionPool(HTTPSConnectionPool):
    """
    Implements an NTLM authentication version of an urllib3 connection pool
    """

    scheme = 'https'

    def __init__(self, user, pw, authurl, *args, **kwargs):
        """
        authurl is a random URL on the server that is protected by NTLM.
        user is the Windows user, probably in the DOMAIN\\username format.
        pw is the password for the user.
        """
        super(NTLMConnectionPool, self).__init__(*args, **kwargs)
        self.authurl = authurl
        self.rawuser = user
        user_parts = user.split('\\', 1)
        self.domain = user_parts[0].upper()
        self.user = user_parts[1]
        self.pw = pw

    def _new_conn(self):
        # Performs the NTLM handshake that secures the connection. The socket
        # must be kept open while requests are performed.
        self.num_connections += 1
        log.debug('Starting NTLM HTTPS connection no. %d: https://%s%s' %
                  (self.num_connections, self.host, self.authurl))

        req_header = 'Authorization'
        resp_header = 'www-authenticate'

        conn = HTTPSConnection(host=self.host, port=self.port)

        headers = {
            'Connection': 'Keep-Alive',
            req_header: f'NTLM {ntlm.create_NTLM_NEGOTIATE_MESSAGE(self.rawuser)}',
        }

        log.debug(f'Request headers: {headers}')
        conn.request('GET', self.authurl, None, headers)
        res = conn.getresponse()
        reshdr = dict(res.getheaders())
        log.debug(f'Response status: {res.status} {res.reason}')
        log.debug(f'Response headers: {reshdr}')
        log.debug(f'Response data: {res.read(100)} [...]')

        # Remove the reference to the socket, so that it can not be closed by
        # the response object (we want to keep the socket open)
        res.fp = None

        # Server should respond with a challenge message
        auth_header_values = reshdr[resp_header].split(', ')
        auth_header_value = None
        for s in auth_header_values:
            if s[:5] == 'NTLM ':
                auth_header_value = s[5:]
        if auth_header_value is None:
            raise Exception(
                f'Unexpected {resp_header} response header: {reshdr[resp_header]}'
            )


        # Send authentication message
        ServerChallenge, NegotiateFlags = \
            ntlm.parse_NTLM_CHALLENGE_MESSAGE(auth_header_value)
        auth_msg = ntlm.create_NTLM_AUTHENTICATE_MESSAGE(ServerChallenge,
                                                         self.user,
                                                         self.domain,
                                                         self.pw,
                                                         NegotiateFlags)
        headers[req_header] = f'NTLM {auth_msg}'
        log.debug(f'Request headers: {headers}')
        conn.request('GET', self.authurl, None, headers)
        res = conn.getresponse()
        log.debug(f'Response status: {res.status} {res.reason}')
        log.debug(f'Response headers: {dict(res.getheaders())}')
        log.debug(f'Response data: {res.read()[:100]} [...]')
        if res.status != 200:
            if res.status == 401:
                raise Exception('Server rejected request: wrong '
                                'username or password')
            raise Exception(f'Wrong server response: {res.status} {res.reason}')

        res.fp = None
        log.debug('Connection established')
        return conn

    def urlopen(self, method, url, body=None, headers=None, retries=3,
                redirect=True, assert_same_host=True):
        if headers is None:
            headers = {}
        headers['Connection'] = 'Keep-Alive'
        return super(NTLMConnectionPool, self).urlopen(method, url, body,
                                                       headers, retries,
                                                       redirect,
                                                       assert_same_host)
