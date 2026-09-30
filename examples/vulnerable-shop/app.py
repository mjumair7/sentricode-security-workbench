"""Intentionally vulnerable scan fixture. Never run or deploy this sample."""
import logging
import pickle
import subprocess
import requests
from flask import request

# Synthetic value for testing detection; never a valid service credential.
API_KEY = 'sc_demo_7f4b62d8c1a095e3_never_valid'


def search(cursor):
    name = request.args.get('name')
    query = f'SELECT * FROM customers WHERE name = {name}'
    cursor.execute(query)


def diagnostic(user):
    command = request.args.get('command')
    subprocess.run(command, shell=True)
    logging.info(user.ssn)
    return pickle.loads(request.data)


def fetch():
    url = request.args.get('url')
    return requests.get(url, verify=False)
