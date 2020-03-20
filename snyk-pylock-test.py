#!/usr/local/bin/python3
import json
import sys
import getopt
from os import getenv, environ, path
from urllib.request import Request, urlopen 

argumentList = sys.argv[1:]
options = "p:f:hjd"

try: 
  arguments, values = getopt.getopt(argumentList, options)
except getopt.error as err:
  print(str(err))
  exit(2)

debug = False
jsonoutput = False
testmode = ""

for currentArgument, currentValue in arguments:
  if (currentArgument in ("-d")):
    print("DEBUG mode enabled", file=sys.stderr)
    debug = True
  if (currentArgument in ("-j")):
    if (debug == True): 
      print("DEBUG: output format set to JSON", file=sys.stderr)
    jsonoutput = True
  if (currentArgument in ("-p")):
    if (debug == True):
      print("DEBUG: package name set to", currentValue, file=sys.stderr)
    testmode = "package"
    packagestring = currentValue
  elif (currentArgument in ("-f")):
    if (debug == True):
      print("DEBUG: freeze requirements set to", currentValue, file=sys.stderr)
    testmode = "freezefile"
    freezefile = currentValue

# basic checks
if (environ.get('SNYK_TOKEN', 'False') == 'False'):
  print("token not set at $SNYK_TOKEN")
  exit(1)

headers = {
  'Content-Type': 'application/json; charset=utf-8',
  'Authorization': 'token %s'
}

headers['Authorization'] = headers['Authorization'] % (getenv("SNYK_TOKEN"))

if ((len(sys.argv) < 3) or (testmode == "")):
  print("\nusage: \n    $", sys.argv[0], "[options] [source]\n")
  print("options:")
  print("   -d")
  print("    enable debug mode")
  print("   -j")
  print("    output results in JSON format")
  print()
  print("source (pick one):")
  print("   -f <input_filename>")
  print("      <input_filename> can be a frozen requirements file or a piplock format file\n")
  print("   -p <package>==<version>")
  print()
  print("examples:")
  print("   ", sys.argv[0], "-f requirements-freeze.txt")
  print("   ", sys.argv[0], "-p django==1.11")
  print("   ", sys.argv[0], "-j -f requirements-freeze.txt")
  print("   ", sys.argv[0], "-dj -p django==1.11")
  print()
  exit(2)
else:
  if (testmode == 'freezefile'):
    if (path.exists(freezefile) == False):
      print("ERROR: specified input file does not exist");
      exit(2)
    with open(freezefile) as f:
      read_data = f.read()
    # determine if format is json (pipfile.lock format) or not (requirements.txt freeze format)
    try:
      package_data = json.loads(read_data)
      print("pipfile.lock format support not yet implemented")
      exit(2)
    except ValueError as e:
      # if error, its not json
      if (debug == True):
        print("DEBUG: parsing as requirements file format", file=sys.stderr)
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

  elif (testmode == 'package'):
    package, version = packagestring.split('==')
    request = Request('https://snyk.io/api/v1/test/pip/%s/%s' % (package, version), headers=headers)


  if (jsonoutput == False):
    resp = json.loads(urlopen(request).read().decode('utf-8'))
    fmt_white = "\033[1;37;40m "
    fmt_end = "\033[0m"

    #sort the vulns by severity, package
    dict_severity = { 'high':0, 'medium': 1, 'low': 2 }

    for vuln in sorted(resp['issues']['vulnerabilities'], key = lambda i: dict_severity[i['severity']]): 
      if (vuln['severity'] == 'low'):
        fmt_severity = "\033[1;34;40m "
      elif (vuln['severity'] == 'medium'):
        fmt_severity = "\033[1;33;40m "
      elif (vuln['severity'] == 'high'):
        fmt_severity = "\033[1;31;40m "
      else:
        fmt_severity = fmt_white

      fmt_package = fmt_severity.replace('[1', '[4').strip()
      fmt_infolink = fmt_white.replace('[1', '[4').strip()

      print()
      print('%s   %s severity vulnerability found in %s' % (fmt_severity, vuln['severity'].capitalize(), fmt_package + vuln['package'] + fmt_end))
      print('%s   Description: %s' % (fmt_white, vuln['title'] + fmt_end))
      print('%s   Info: %s' % (fmt_white, fmt_infolink + vuln['url'] + fmt_end))
      print('%s   Introduced through: %s' % (fmt_white, str(vuln['from']) + fmt_end))
      print
      print()

  else:
    resp = urlopen(request).read()
    print(resp.decode('utf-8'))
  
