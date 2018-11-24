# coding: utf-8
"""Classes for authentication servers backends"""

import configparser
import importlib
import re

__author__ = 'Florent Captier <florent@captier.org>'


def from_config_file(files):
    servers = {}
    config = configparser.ConfigParser()
    config.read(files)
    for s in config.sections():
        m = re.match('^auth_server_(.*)$', s)
        if m:
            name = m[1]
            options = dict(config.items(s))
            cls = options.pop('class')
            module = importlib.import_module('.'.join(cls.split('.')[:-1]))
            cls = getattr(module, cls.split('.')[-1])
            servers[name] = cls(**options)
    
    return servers


class BaseAuthServer(object):
    pass


class OAuth2AuthServer(BaseAuthServer):
    def __init__(self, authorization_endpoint, token_endpoint):
        # Properties from base RFC 6749
        self.authorization_endpoint = authorization_endpoint
        self.token_endpoint = token_endpoint