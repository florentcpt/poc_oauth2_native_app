import json
import time

from .types import TokenType


class TokenResponse(object):
    """
    >>> payload = '''{
    ...   "access_token": "foo_access_token",
    ...   "expires_in": 3600,
    ...   "refresh_token": "foo_refresh_token",
    ...   "scope": "profile email",
    ...   "token_type": "Bearer",
    ...   "id_token": "foo_id_token"
    ... }'''
    >>> tr = TokenResponse().set_from_json(payload)
    >>> tr.access_token
    'foo_access_token'
    """

    def __init__(self):
        self.access_token = ''
        self.expires_in = 0
        self.refresh_token = ''
        self.scope = ''
        self.token_type = ''
        self.id_token = ''

        self._creation_time = None
    
    @property
    def expiry_time(self):
        return self._creation_time + self.expires_in
    
    @property
    def scopes(self):
        """
        Return scopes as a list
        """
        return self.scope.split(' ')
    
    def set_from_json(self, payload):
        payload = json.loads(payload)
        self._creation_time = time.time()
        for (k, v) in payload.items():
            if not hasattr(self, k):
                raise KeyError('%s is not a valid attribute for a token response' % k)
            setattr(self, k, v)
        return self
    
    def remaining_validity(self):
        return self.expiry_time - time.time()
    
    def is_access_token_valid(self):
        return self.remaining_validity > 0


class BaseTokenStorage(object):

    def __init__(self):
        self.__storage = {}
        self._load()
    
    @property
    def authz_endpoints(self):
        return self.__storage.keys()

    def get_token(self, authz_endpoint):
        return self.__storage[authz_endpoint]
    
    def set_token(self, authz_endpoint, token):
        self.__storage[authz_endpoint] = token
        self._save()
    
    def _save(self):
        raise NotImplementedError
    
    def _load(self):
        raise NotImplementedError


class BasicTokenStorage(BaseTokenStorage):
    """
    Really basic storage only using current execution memory.
    This SHOULD NOT be used in production.

    >>> token = TokenResponse()
    >>> token.access_token = 'foo'
    >>> store = BasicTokenStorage()
    >>> store.set_token('https://domain.example.com/authz', token)
    >>> token == store.get_token('https://domain.example.com/authz')
    True
    """

    def _save(self):
        pass
    
    def _load(self):
        pass