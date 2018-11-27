# coding: utf-8
"""Token storages models"""

from __future__ import unicode_literals, absolute_import
import json
import time

__author__ = 'Florent Captier <florent@captier.org>'


class TokenResponse(object):

    def __init__(self, access_token='', expires_in=0, refresh_token='', scope='', token_type='', id_token=''):
        self.save(access_token, expires_in, refresh_token, scope, token_type, id_token)
    
    def save(self, access_token, expires_in, refresh_token, scope, token_type, id_token):
        self.access_token = access_token
        self.expires_in = expires_in
        self.refresh_token = refresh_token
        self.scope = scope
        self.token_type = token_type
        self.id_token = id_token

        self._creation_time = time.time()
    
    @property
    def expiry_time(self):
        return self._creation_time + self.expires_in
    
    @property
    def scopes(self):
        """
        Return scopes as a list
        """
        return self.scope.split(' ')
    
    @classmethod
    def from_json_response(cls, payload):
        """
        >>> payload = '''{
        ...   "access_token": "foo_access_token",
        ...   "expires_in": 3600,
        ...   "refresh_token": "foo_refresh_token",
        ...   "scope": "profile email",
        ...   "token_type": "Bearer",
        ...   "id_token": "foo_id_token"
        ... }'''
        >>> tr = TokenResponse.from_json_response(payload)
        >>> tr.access_token
        'foo_access_token'
        """
        payload = json.loads(payload)
        return cls(**payload)
    
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

    >>> token = TokenResponse(access_token='foo')
    >>> store = BasicTokenStorage()
    >>> store.set_token('https://domain.example.com/authz', token)
    >>> token == store.get_token('https://domain.example.com/authz')
    True
    """

    def _save(self):
        pass
    
    def _load(self):
        pass