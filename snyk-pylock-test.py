#!/usr/local/bin/python3
'''
Reports issue data (vulnerabilities and licenses) from a requirements.txt
format (and soon to be Pipfile.lock format) file using the Snyk Test API for PIP.
'''
import json
import sys
import getopt
from os import getenv, environ, path
from urllib.request import Request, urlopen

argument_list = sys.argv[1:]
OPTIONS = "p:f:hjd"

try:
    arguments, values = getopt.getopt(argument_list, OPTIONS)
except getopt.error as err:
    print(str(err))
    sys.exit(2)

DEBUG = False
JSONOUTPUT = False
TESTMODE = ""

for current_argument, current_value in arguments:
    if current_argument in "-d":
        print("DEBUG mode enabled", file=sys.stderr)
        DEBUG = True
    if current_argument in "-j":
        if DEBUG:
            print("DEBUG: output format set to JSON", file=sys.stderr)
        JSONOUTPUT = True
    if current_argument in "-p":
        if DEBUG:
            print("DEBUG: package name set to", current_value, file=sys.stderr)
        TESTMODE = "package"
        package_string = current_value
    elif current_argument in "-f":
        if DEBUG:
            print("DEBUG: freeze requirements set to", current_value, file=sys.stderr)
        TESTMODE = "freezefile"
        FREEZEFILE = current_value

# basic checks
if environ.get('SNYK_TOKEN', 'False') == 'False':
    print("token not set at $SNYK_TOKEN")
    sys.exit(1)

HEADERS = {
    'Content-Type': 'application/json; charset=utf-8',
    'Authorization': 'token %s'
}

HEADERS['Authorization'] = HEADERS['Authorization'] % getenv("SNYK_TOKEN")

if ((len(sys.argv) < 3) or (TESTMODE == "")):
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
    sys.exit(2)
else:
    if TESTMODE == 'freezefile':
        if not path.exists(FREEZEFILE):
            print("ERROR: specified input file does not exist")
            sys.exit(2)
        with open(FREEZEFILE) as f:
            read_data = f.read()
            # determine if format is json (pipfile.lock format)
            # or not (requirements.txt freeze format)
            try:
                package_data = json.loads(read_data)
                print("pipfile.lock format support not yet implemented")
                sys.exit(2)
            except ValueError:
                # if error, its not json
                if DEBUG:
                    print("DEBUG: parsing as requirements file format", file=sys.stderr)
                package_data = read_data.replace('\n', '\\n').rstrip('\\n')

                VALUES = """
                    {
                        "encoding": "plain",
                        "files": {
                            "target": {
                                "contents": "%s"
                            }
                        }
                    }
                """

                VALUES = VALUES % (package_data)
                request = Request('https://snyk.io/api/v1/test/pip', \
                    VALUES.encode('utf-8'), headers=HEADERS)

    elif TESTMODE == 'package':
        PACKAGE, VERSION = package_string.split('==')
        request = Request('https://snyk.io/api/v1/test/pip/%s/%s' \
            % (PACKAGE, VERSION), headers=HEADERS)

    if not JSONOUTPUT:
        resp = json.loads(urlopen(request).read().decode('utf-8'))
        FMT_WHITE = "\033[1;37;40m "
        FMT_END = "\033[0m"

        #sort the vulns by severity, package
        SEVERITY_LOOKUP = {
            'critical': 0,
            'high': 1,
            'medium': 2,
            'low': 3
        }

        for vuln in sorted(resp['issues']['vulnerabilities'], \
            key=lambda i: SEVERITY_LOOKUP[i['severity']]):
            if vuln['severity'] == 'low':
                FMT_SEVERITY = "\033[1;34;188;187;200;40m "
            elif vuln['severity'] == 'medium':
                FMT_SEVERITY = "\033[1;33;237;213;94;40m "
            elif vuln['severity'] == 'high':
                FMT_SEVERITY = "\033[1;31;255;135;47;40m "
            elif vuln['severity'] == 'critical':
                FMT_SEVERITY = "\033[1;31;255;11;11;40m "
            else:
                FMT_SEVERITY = FMT_WHITE

            FMT_PACKAGE = FMT_SEVERITY.replace('[1', '[4').strip()
            FMT_INFOLINK = FMT_WHITE.replace('[1', '[4').strip()

            print()
            print('%s   %s severity vulnerability found in %s' \
                % (FMT_SEVERITY, vuln['severity'].capitalize(), \
                FMT_PACKAGE + vuln['package'] + FMT_END))
            print('%s   Description: %s' % (FMT_WHITE, vuln['title'] + FMT_END))
            print('%s   Info: %s' % (FMT_WHITE, FMT_INFOLINK + vuln['url'] + FMT_END))
            print('%s   Introduced through: %s' % (FMT_WHITE, str(vuln['from']) + FMT_END))
            print()
            print()

    else:
        resp = urlopen(request).read()
        print(resp.decode('utf-8'))
