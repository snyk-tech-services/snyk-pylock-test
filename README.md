# snyk-pylock-test
A wrapper script that produces issues data (vulernabilties and licenses) from a requirements.txt format (and soon to be Pipfile.lock format) file using the [Snyk Test API for PIP](https://snyk.docs.apiary.io/#reference/test/pip).

At the time of building this, the Snyk CLI requires an environment where the packages in requirements.txt are installable in order to run 'snyk test' successfully.  This is a workaround for users who would like to simply get a list of issues at the command line from a static list of packages and versions for a python project without an environment to install them.

This script can also output the results in json format. [jq](https://stedolan.github.io/jq/download/) and [snyk-to-html](https://github.com/snyk/snyk-to-html) can be used quite easily to generate an HTML report of the results that can be shared, as described in the _Generate HTML Report_ section

## Prerequisites
- Python 3 
- API Token set in ```SNYK_TOKEN``` environment variable

## Usage
```usage:
    $ ./snyk-pylock-test.py [options] [source]

options:
   -d
    enable debug mode
   -j
    output results in JSON format

source (pick one):
   -f <input_filename>
      <input_filename> can be a frozen requirements file or a piplock format file

   -p <package>==<version>

examples:
    ./snyk-pylock-test.py -f requirements-freeze.txt
    ./snyk-pylock-test.py -p django==1.11
    ./snyk-pylock-test.py -j -f requirements-freeze.txt
    ./snyk-pylock-test.py -dj -p django==1.11
```

## Generate HTML Report
The JSON output can be provided to the snyk-to-html utility by way of jq to produce an HTML report.  See [sample_results.html](https://github.com/snyk-tech-services/snyk-pylock-test/blob/master/sample_results.html) provided.  

To put it all together:

```./snyk-pylock-test.py -j -f sample_requirements.txt | jq '.issues' | snyk-to-html -o sample_results.html```

  Output:
  ```
        Vulnerability snapshot saved at sample_results.html
  ```

## Todo
- Put JSON parsing inside the python script so ```jq``` is not required
- provide support for Pipfile.lock format files
- base64 encode API input for efficiency
- port to Typescript
- include Remediation advice in the terminal output
- set exit code 1 if vulns are found
