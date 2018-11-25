import configparser
import json
import logging
import requests
from oauth2_client.requests.AuthClasses import NativeAppAuth
import oauth2_client


def main():
    config_files = ['default_config.ini', 'config.ini']

    config = configparser.ConfigParser()
    config.read(config_files)

    auth_servers = oauth2_client.servers.from_config_file(config_files)
    auth_server = auth_servers[config.get('oauth2', 'authz_server')]

    session = requests.Session()
    session.auth = NativeAppAuth(
        authz_server=auth_server,
        client_id=config.get('oauth2', 'client_id'),
        client_secret=config.get('oauth2', 'client_secret'))
    res = session.get(auth_server.userinfo_endpoint)
    print(res.json())


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    main()