import collections
import pytest

import oauth2_client

@pytest.fixture
def oauth2_authz_server():
    authz_endpoint = 'https://as.example.com/oauth2/auth'
    token_endpoint = 'https://as.example.com/oauth2/token'

    return oauth2_client.servers.OAuth2AuthServer(authz_endpoint, token_endpoint)


@pytest.fixture
def fake_listener_process():
    Process = collections.namedtuple('Process', ['httpd', ])
    HttpServer = collections.namedtuple('HttpServer', ['server_address', ])

    http_server = HttpServer(server_address=('127.0.0.1', 8080))
    process = Process(httpd=http_server)

    return process

@pytest.fixture
def native_app_auth(oauth2_authz_server, fake_listener_process):
    client_id = 'clientid'
    client_secret = 'clientsecret'

    native_app_auth = oauth2_client.requests.AuthClasses.NativeAppAuth(oauth2_authz_server, client_id, client_secret)
    native_app_auth._listener_process = fake_listener_process

    return native_app_auth

class TestNativeAppAuth():
    def test_init(self, oauth2_authz_server):
        with pytest.raises(AssertionError):
            oauth2_client.requests.AuthClasses.NativeAppAuth('foo', 'clientid', 'clientsecret')

    def test_authz_url(self, native_app_auth):
        assert native_app_auth.redirect_uri == 'http://127.0.0.1:8080/oauth2_redirect.html'
        assert native_app_auth.authz_url == 'https://as.example.com/oauth2/auth?client_id=clientid&redirect_uri=http%3A%2F%2F127.0.0.1%3A8080%2Foauth2_redirect.html&response_type=code&scope=email+profile'