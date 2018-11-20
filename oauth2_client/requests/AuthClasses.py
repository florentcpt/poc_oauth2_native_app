import inspect
from urllib.parse import urlencode, urlsplit, parse_qs
from urllib.request import urlopen
from http.server import SimpleHTTPRequestHandler, HTTPServer
import os
import threading
import webbrowser
import requests
from ..TokenStorages import BasicTokenStorage, BaseTokenStorage, TokenResponse

_authz_response_params = None


class _OAuth2RedirectHTTPRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.redirect_path = NativeAppAuth.REDIRECT_PATH
        directory = os.path.join(os.path.dirname(__file__), 'listener_resources')
        super(_OAuth2RedirectHTTPRequestHandler, self).__init__(*args, directory=directory, **kwargs)

    def do_GET(self):
        global _authz_response_params
        if urlsplit(self.path).path == self.redirect_path:
            _authz_response_params = parse_qs(urlsplit(self.path).query)
        super(_OAuth2RedirectHTTPRequestHandler, self).do_GET()

    def log_request(self, code='-', size='-'):
        pass


class _ListenerThread(threading.Thread):
    THREAD_NAME = 'oauth2_listener'

    def __init__(self, server_port=0, server_class=HTTPServer, handler_class=_OAuth2RedirectHTTPRequestHandler):
        server_address = ('127.0.0.1', server_port)
        self.httpd = server_class(server_address, handler_class)
        super(_ListenerThread, self).__init__(name=self.THREAD_NAME)
    
    def run(self):
        self.httpd.handle_request()


class NativeAppAuth(requests.auth.AuthBase):
    """
    >>> o = NativeAppAuth(token_storage_class='foo')
    Traceback (most recent call last):
        ...
    AssertionError: token_storage_class MUST be a subclass of BaseTokenStorage
    """

    DEFAULT_SCOPES = ['profile', 'email']
    DEFAULT_TOKEN_STORAGE = BasicTokenStorage
    REDIRECT_PATH = '/oauth2_redirect.html'

    def __init__(self, authz_endpoint, token_endpoint, client_id, client_secret, *args, scopes=DEFAULT_SCOPES, token_storage_class=DEFAULT_TOKEN_STORAGE, **kwargs):
        assert inspect.isclass(token_storage_class) and issubclass(token_storage_class, BaseTokenStorage), "token_storage_class MUST be a subclass of BaseTokenStorage"
        
        self.authz_endpoint = authz_endpoint
        self.token_endpoint = token_endpoint
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = scopes

        self._token_storage = token_storage_class()
        self._listener_thread = None
        self._authorization_code = None

    def __call__(self, r):
        (server_host, server_port) = self.run_local_listener()
        redirect_uri = 'http://%s:%i%s' % (server_host, server_port, NativeAppAuth.REDIRECT_PATH)
        # print('Started local HTTP listener on %s' % redirect_uri)
        # print('Start consent flow with %s' % config['oauth2']['authz_endpoint'])
        self.start_consent_flow(redirect_uri)
        # print('Got authorization code: %s' % get_authz_code())
        self._token_storage.set_token(self.authz_endpoint, self.get_token(self.get_authz_code(), redirect_uri))
        # print('Got access token: %s' % token_store.get_token(config['oauth2']['authz_endpoint']).access_token)
        r.headers['Authorization'] = 'Bearer %s' % self._token_storage.get_token(self.authz_endpoint).access_token
        return r
    
    @classmethod
    def from_config_doc(config_endpoint, client_id, client_secret, scopes=DEFAULT_SCOPES, token_storage_class=DEFAULT_TOKEN_STORAGE):
        raise NotImplementedError()
    
    def get_authz_url(self, redirect_uri):
        """
        Get the OAuth2 authorization URL to send the authorization request to.

        >>> get_authz_url('https://domain.example.com/auth', 'http://127.0.0.1:8900', 'client_id')
        'https://domain.example.com/auth?client_id=client_id&redirect_uri=http%3A%2F%2F127.0.0.1%3A8900&response_type=code&scope=email+profile'

        :param str redirect_uri: The URI on which the authorization server should redirect the user on (should be on loopback address)
        :param str client_id: The client id used to identify this client
        :param list scopes: List of scopes to ask in the token
        :return str: Full URL to open to start an OAuth2 authorization flow
        """
        query_params = urlencode({
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': ' '.join(self.scopes),
        })
        return '{}?{}'.format(self.authz_endpoint, query_params)


    def get_authz_code(self):
        return _authz_response_params['code'][0]


    def get_token(self, authz_code, redirect_uri):
        data = urlencode({
            'code': authz_code,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code',
            #'code_verifier': '',
        })
        with urlopen(self.token_endpoint, data=data.encode('ASCII')) as response:
            return TokenResponse.from_json_response(response.read().decode('UTF-8'))


    def run_local_listener(self):
        self._listener_thread = _ListenerThread(server_class=HTTPServer, handler_class=_OAuth2RedirectHTTPRequestHandler)
        self._listener_thread.start()
        return self._listener_thread.httpd.server_address


    def start_consent_flow(self, redirect_uri):
        webbrowser.open_new_tab(self.get_authz_url(redirect_uri))
        self._listener_thread.join()
