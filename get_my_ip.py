#!/usr/bin/env python3

import argparse
import json
import logging
import random
import requests
import sys
import socket
import re
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

def arguments():
    """Create and return arguments"""
    parser = argparse.ArgumentParser(description='Get your IP address from a semi-random website')
    parser.add_argument('-l', '--loglevel', help='Set loglevel (debug, info, warn, error, critical)', required=False, default='info')
    parser.add_argument('-t', '--test-all', help='Test all sites', required=False, dest='test_all', action='store_true')
    return parser.parse_args()

def configure_logging(arguments):
    """Basic configurations"""
    date_format = '%Y-%m-%d %H:%M:%S'
    logging.basicConfig(format='%(asctime)s %(levelname)-4s: %(message)s', datefmt=date_format)
    loglevel = arguments.loglevel.lower()

    if loglevel == 'debug':
        logging.getLogger().setLevel(logging.DEBUG)
    if loglevel == 'info':
        logging.getLogger().setLevel(logging.INFO)
    if loglevel == 'warn' or loglevel == 'warning':
        logging.getLogger().setLevel(logging.WARNING)
    if loglevel == 'error':
        logging.getLogger().setLevel(logging.ERROR)
    if loglevel == 'critical':
        logging.getLogger().setLevel(logging.CRITICAL)

def load_file():
    with open("list.json", "r") as config_file:
        json_blob = json.load(config_file)

    return json_blob

def valid_ip(address):
    # Private addresses and other things to ignore
    if address.startswith('192.168') or \
       address.startswith('10.') or \
       address.startswith('172.') or \
       address.endswith('.0') or \
       address == '127.0.0.1':
        return False
    try: 
        socket.inet_aton(address)
        print(address)
        return True
    except:
        return False

def get_site(url):
    try:
        headers = { 'User-Agent': 'curl/7.54.0' }
        #request = requests.head(website, timeout=1)
        request = requests.get(url, timeout=1, headers=headers)        
        if request.status_code < 400:
            logging.debug("Website {} is up".format(url))
            return request
        else:
            logging.debug("Website {} is down. Trying another...".format(url))
            return None
    except:
        logging.debug("Getting {} threw an exception...".format(url))
        return None

def try_all_sites(site_list):
    for site in site_list['ipv4_websites']:
        s = get_site(site)
        if s:
            get_ip(s)
        else:
            logging.warning("{} cannot be reached...".format(site))

def get_random_site(site_list):
    i = 0
    while i < 10:
        i += 1
        secure_random = random.SystemRandom()
        random_site = secure_random.choice(site_list['ipv4_websites'])
        site = get_site(random_site)
        if site:
            return site

    logging.error("Could not connect to any site in 10 tries. Maybe your connection is down?")
    sys.exit(1)

def get_ip(site):
    ip_found = False

    stripped_text = re.sub("[^0-9^.]", "", site.text)
    if valid_ip(stripped_text):
        return

    soup = BeautifulSoup(site.text, features="lxml")
    ip_pattern = "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"

    ip_list = soup.find_all(text=re.compile(ip_pattern))
    unique_list = set(ip_list)

    for ip in unique_list:
        valid_ip(ip)
        ip_found = True

    if not ip_found:
        logging.error("No IP address found using {}".format(site.url))
        #sys.exit(1)
    return

def main():
    """Main function"""
    args = arguments()
    configure_logging(args)
    site_list = load_file()
    if args.test_all:
        try_all_sites(site_list)
    else:
        random_site = get_random_site(site_list)
        get_ip(random_site)

if __name__ == "__main__":
    main()
