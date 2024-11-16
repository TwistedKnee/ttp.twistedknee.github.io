# lab 1 sql injection vuln in where clause allowing retrieval of hidden data

import requests
import sys
import urllib3

proxies = {'http':'http://127.0.0.1:8080', 'https':'https://127.0.0.1:8080'}



if __name__ == '__main__':
  try:
    url = sys.argv[1].strip()
    payload = sys.argv[2].strip()
  except indexError:
    print("[-] Usage: %s <url> <payload>" % sys.argv[0])
    print('[-] Example: %s www.example.com "1=1"' % sys.argv[0])
    sys.exit(-1)
