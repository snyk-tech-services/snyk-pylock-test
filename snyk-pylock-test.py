import json
import sys
from os import getenv, environ, path
from urllib.request import Request, urlopen 

# basic checks
if (environ.get('SNYK_TOKEN', 'False') == 'False'):
  print("token not set at $SNYK_TOKEN")
  exit(1)

if (len(sys.argv) != 2):
  print("usage: ", sys.argv[0], "<input_filename>")
  print("<input_filename> can be a frozen requirements file or a piplock format file")
  print();
  exit(1)
else:
  lockfile = sys.argv[1]

if (path.exists(lockfile) == False):
  print("specified input file does not exist");
  exit(1)
  
with open(sys.argv[1]) as f:
  read_data = f.read()

# determine if format is json (pipfile.lock format) or not (requirements.txt freeze format)
try:
  package_data = json.loads(read_data)
  print("pipfile.lock format support not yet implemented")
  exit(1)
except ValueError as e:
  # if error, its not json
  print("info: parsing as requirements file format", file=sys.stderr)
  package_data = read_data.replace('\n','\\n').rstrip('\\n')

values = """
  {
    "encoding": "plain",
    "files": {
      "target": {
        "contents": "%s"
      }
    }
  }
"""

values = values % (package_data)

headers = {
  'Content-Type': 'application/json; charset=utf-8',
  'Authorization': 'token %s'
}

headers['Authorization'] = headers['Authorization'] % (getenv("SNYK_TOKEN"))

request = Request('https://snyk.io/api/v1/test/pip', values.encode('utf-8'), headers=headers)
resp = urlopen(request).read()
print(resp.decode('utf-8'))

