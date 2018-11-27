from __future__ import unicode_literals, absolute_import
import inspect
try:
    from urllib.parse import urlencode, urlsplit, parse_qs
    from urllib.request import urlopen
except ImportError:
    from urllib import urlencode, urlopen
    from urlparse import urlsplit, parse_qs
try:
    from http.server import SimpleHTTPRequestHandler, HTTPServer
except ImportError:
    from BaseHTTPServer import HTTPServer
    from SimpleHTTPServer import SimpleHTTPRequestHandler
import logging
import os
import multiprocessing
import webbrowser
import requests
from ...models.tokenStorages import BasicTokenStorage, BaseTokenStorage, TokenResponse
from ...models.servers import BaseAuthServer

__logger__ = logging.getLogger(__name__)


class _OAuth2RedirectHTTPRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.redirect_path = NativeAppAuth.REDIRECT_PATH
        directory = os.path.join(os.path.dirname(__file__), 'listener_resources')
        super(_OAuth2RedirectHTTPRequestHandler, self).__init__(*args, directory=directory, **kwargs)

    def do_GET(self):
        if urlsplit(self.path).path == self.redirect_path:
            self.server.authz_response_params = parse_qs(urlsplit(self.path).query)
        super(_OAuth2RedirectHTTPRequestHandler, self).do_GET()

    def log_request(self, code='-', size='-'):
        pass


class _ListenerProcess(multiprocessing.Process):
    PROCESS_NAME = 'oauth2_listener'

    def __init__(self, conn, server_port=0, server_class=HTTPServer, handler_class=_OAuth2RedirectHTTPRequestHandler):
        server_address = ('127.0.0.1', server_port)
        self.httpd = server_class(server_address, handler_class)
        self.conn = conn
        super(_ListenerProcess, self).__init__(name=self.PROCESS_NAME)
    
    def run(self):
        __logger__.debug('Start listener for consent redirection on http://%s:%i' % self.httpd.server_address)
        # Loop until the listener received the authorization code
        while not hasattr(self.httpd, 'authz_response_params'):
            self.httpd.handle_request()
        # Send the code over the pipe to the parent process
        self.conn.send(self.httpd.authz_response_params)


class NativeAppAuth(requests.auth.AuthBase):
    """
    Authentication class for native apps
    """

    DEFAULT_SCOPES = ['profile', 'email']
    DEFAULT_TOKEN_STORAGE = BasicTokenStorage
    REDIRECT_PATH = '/oauth2_redirect.html'

    def __init__(self, authz_server, client_id, client_secret, scopes=['email', 'profile'], token_storage_class=BasicTokenStorage, **kwargs):
        """
        :param BaseAuthServer authz_server: Authorization server to be used
        """

        assert inspect.isclass(token_storage_class) and issubclass(token_storage_class, BaseTokenStorage), "token_storage_class MUST be a subclass of BaseTokenStorage"
        assert isinstance(authz_server, BaseAuthServer), "authz_server MUST be an instance of BaseAuthServer"
        
        self.authz_server = authz_server
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = scopes

        self._token_storage = token_storage_class()
        self._listener_process = None
        self._authorization_code = None
    
    @property
    def redirect_uri(self):
        (listener_host, listener_port) = self._listener_process.httpd.server_address
        return 'http://%s:%i%s' % (listener_host, listener_port, NativeAppAuth.REDIRECT_PATH)

    def __call__(self, r):
        self.start_consent_flow()
        self._token_storage.set_token(self.authz_server.authorization_endpoint, self.get_token(self.authz_code))
        r.headers['Authorization'] = 'Bearer %s' % self._token_storage.get_token(self.authz_server.authorization_endpoint).access_token
        return r
    
    @classmethod
    def from_config_doc(config_endpoint, client_id, client_secret, scopes=DEFAULT_SCOPES, token_storage_class=DEFAULT_TOKEN_STORAGE):
        raise NotImplementedError()
    
    @property
    def authz_url(self):
        """
        Get the OAuth2 authorization URL to send the authorization request to.

        :return str: Full URL to open to start an OAuth2 authorization flow
        """
        query_params = urlencode({
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'scope': ' '.join(self.scopes),
        })
        return '{}?{}'.format(self.authz_server.authorization_endpoint, query_params)

    @property
    def authz_code(self):
        return self._authz_response_params['code'][0]


    def get_token(self, authz_code):
        data = urlencode({
            'code': authz_code,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'redirect_uri': self.redirect_uri,
            'grant_type': 'authorization_code',
            #'code_verifier': '',
        })
        with urlopen(self.authz_server.token_endpoint, data=data.encode('ASCII')) as response:
            token = TokenResponse.from_json_response(response.read().decode('UTF-8'))
        
        __logger__.debug('Got access token: %s' % token.access_token)

        return token

    def start_consent_flow(self):
        (parent_conn, child_conn) = multiprocessing.Pipe()
        self._listener_process = _ListenerProcess(child_conn)
        self._listener_process.start()
        __logger__.debug('Start consent flow with: %s' % self.authz_server.authorization_endpoint)
        webbrowser.open_new_tab(self.authz_url)
        self._authz_response_params = parent_conn.recv()
        self._listener_process.join()
        __logger__.debug('Got authorization code: %s' % self.authz_code)
