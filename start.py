import configparser
import json
import requests
from oauth2_client.requests.AuthClasses import NativeAppAuth


def main():
    config = configparser.ConfigParser()
    config.read(['default_config.ini', 'config.ini'])

    session = requests.Session()
    session.auth = NativeAppAuth(config['oauth2']['authz_endpoint'], config['oauth2']['token_endpoint'], config['oauth2']['client_id'], config['oauth2']['client_secret'])
    res = session.get(config['oauth2']['userinfo_endpoint'])
    print(res.json())


if __name__ == '__main__':
    main()