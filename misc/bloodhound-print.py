#!/usr/bin/env python3

"""
Print all node names to console (useful when developing the report).

Example:
$ bloodhound-print.py '<QUERY>'
"""

import sys, json
from pathlib import Path
from neo4j import GraphDatabase

configjson = Path.home() / '.config' / 'bloodhound' / 'config.json'
with open(configjson, 'r') as f:
	config = json.load(f)

try:
	username = config['databaseInfo']['user']
except KeyError:
	username = 'neo4j'

try:
	password = config['databaseInfo']['password']
except KeyError:
	password = None

uri = "bolt://localhost:7687"
driver = GraphDatabase.driver(uri, auth=(username, password), encrypted=False)

with driver.session() as session:
	with session.begin_transaction() as tx:
		result = tx.run(sys.argv[1])

uniq = set()
for record in result.data():
	for path in record['p']:
		for node in path.nodes:
			name = node['name']
			if name not in uniq:
				uniq.add(name)

for name in sorted(uniq):
	print(name)
