import configparser
from http.server import SimpleHTTPRequestHandler, HTTPServer, HTTPStatus
import socket
import threading
import webbrowser
from urllib.parse import urlencode, urlsplit, parse_qs
from urllib.request import urlopen
import time
import json
import os

import requests

from oauth2_client.TokenStorages import TokenResponse, BasicTokenStorage

tokenStorageClass = BasicTokenStorage
_authz_qp = ''
_redirect_path = '/oauth2_redirect.html'
_listener_thread_name = 'oauth2_listener'
_listener_thread = None


class OAuth2RedirectHTTPRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        directory = os.path.join(os.getcwd(), 'listener_resources')
        super(OAuth2RedirectHTTPRequestHandler, self).__init__(*args, directory=directory, **kwargs)

    def do_GET(self):
        global _authz_qp
        if urlsplit(self.path).path == _redirect_path:
            _authz_qp = parse_qs(urlsplit(self.path).query)
        super(OAuth2RedirectHTTPRequestHandler, self).do_GET()

    def log_request(self, code='-', size='-'):
        pass


def get_authz_url(oauth2_authz_endpoint, redirect_uri, client_id, scopes=['email', 'profile']):
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
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': ' '.join(scopes),
    })
    return '{}?{}'.format(oauth2_authz_endpoint, query_params)


def get_authz_code():
    return _authz_qp['code'][0]


def get_token(token_endpoint, authz_code, client_id, client_secret, redirect_uri):
    data = urlencode({
        'code': authz_code,
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code',
        #'code_verifier': '',
    })
    with urlopen(token_endpoint, data=data.encode('ASCII')) as response:
        return TokenResponse().set_from_json(response.read().decode('UTF-8'))


def run_local_listener(server_class=HTTPServer, handler_class=OAuth2RedirectHTTPRequestHandler):
    global _listener_thread
    server_address = ('127.0.0.1', 0)
    httpd = server_class(server_address, handler_class)
    _listener_thread = threading.Thread(name=_listener_thread_name, target=httpd.handle_request)
    _listener_thread.start()
    return httpd.server_address


def start_consent_flow(authz_endpoint, redirect_uri, client_id):
    webbrowser.open_new_tab(get_authz_url(authz_endpoint, redirect_uri, client_id))
    _listener_thread.join()


def main():
    global _authz_qp

    config = configparser.ConfigParser()
    config.read(['default_config.ini', 'config.ini'])

    _authz_qp = None
    token_store = tokenStorageClass()
    (server_host, server_port) = run_local_listener()
    redirect_uri = 'http://%s:%i%s' % (server_host, server_port, _redirect_path)
    print('Started local HTTP listener on %s' % redirect_uri)
    print('Start consent flow with %s' % config['oauth2']['authz_endpoint'])
    start_consent_flow(config['oauth2']['authz_endpoint'], redirect_uri, config['oauth2']['client_id'])
    print('Got authorization code: %s' % get_authz_code())
    token_store.set_token(config['oauth2']['authz_endpoint'], get_token(config['oauth2']['token_endpoint'], get_authz_code(), config['oauth2']['client_id'], config['oauth2']['client_secret'], redirect_uri))
    print('Got access token: %s' % token_store.get_token(config['oauth2']['authz_endpoint']).access_token)

    # Now call the API
    res = requests.get(config['oauth2']['userinfo_endpoint'], headers={'Authorization': 'Bearer %s' % token_store.get_token(config['oauth2']['authz_endpoint']).access_token})
    print(res.json())


if __name__ == '__main__':
    main()