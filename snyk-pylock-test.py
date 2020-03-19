#!/usr/local/bin/python3
import json
import sys
from os import getenv, environ, path
from urllib.request import Request, urlopen 

# basic checks
if (environ.get('SNYK_TOKEN', 'False') == 'False'):
  print("token not set at $SNYK_TOKEN")
  exit(1)

headers = {
  'Content-Type': 'application/json; charset=utf-8',
  'Authorization': 'token %s'
}

headers['Authorization'] = headers['Authorization'] % (getenv("SNYK_TOKEN"))

if (len(sys.argv) != 3):
  print("\nusage: ", sys.argv[0], "[ -f <input_filename> | -p <package>@<version> ]\n")
  print("<input_filename> can be a frozen requirements file or a piplock format file\n")
  print("Examples: \n")
  print("     ", sys.argv[0], "-f requirements-freeze.txt")
  print("     ", sys.argv[0], "-p regexgen@1.0.1")
  print()
  exit(1)
else:
  mode = sys.argv[1]
  if (mode == '-f'):
    lockfile = sys.argv[2]
    if (path.exists(lockfile) == False):
      print("specified input file does not exist");
      exit(1)
    with open(lockfile) as f:
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
      request = Request('https://snyk.io/api/v1/test/pip', values.encode('utf-8'), headers=headers)

  elif (mode == '-p'):
    packagestring = sys.argv[2]
    package, version = packagestring.split('==')
    request = Request('https://snyk.io/api/v1/test/pip/%s/%s' % (package, version), headers=headers)

  #resp = urlopen(request).read()
  #  print(resp.decode('utf-8'))
  resp = json.loads(urlopen(request).read().decode('utf-8'))
  #print(resp)
  colorwhite = "\033[0;37;40m "

  for vuln in resp['issues']['vulnerabilities']: 
    if (vuln['severity'] == 'low'):
      color="\033[1;34;40m "
    elif (vuln['severity'] == 'medium'):
      color="\033[1;33;40m "
    elif (vuln['severity'] == 'high'):
      color="\033[1;31;40m "
    else:
      color="\033[1:37;40m "

    print()
    print('  %s %s severity vulnerability found in %s' % (color, vuln['severity'], vuln['package']))
    print('  %s Description: %s' % (colorwhite, vuln['title']))
    print('  %s Info: %s' % (colorwhite, vuln['url']))
    print('  %s Introduced through: %s' % (colorwhite, vuln['from']))
    print()
  
