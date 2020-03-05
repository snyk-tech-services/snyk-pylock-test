# snyk-pylock-test
A simple wrapper script that produces issues data (vulernabilties and licenses) from a requirements.txt format (and soon to be Pipfile.lock format) file using the [Snyk Test API for PIP](https://snyk.docs.apiary.io/#reference/test/pip).

At the time of building this, the Snyk CLI requires an environment where the packages in requirements.txt are installable in order to run 'snyk test' successfully.  This is a workaround for users who would like to simply get a list of issues from a static list of packages and versions for a python project without an environment to install them.

This script will output the results in json format. [jq](https://stedolan.github.io/jq/download/) and [snyk-to-html](https://github.com/snyk/snyk-to-html) can be used quite easily to generate an HTML report of the results that can be shared, as described in the _Generate HTML Report_ section

## Prerequisites
- Python 3 
- API Token set in ```SNYK_TOKEN``` environment variable

## Usage
```python3 snyk-pylock-test.py <requirements_file>```

To use the provided example file
```python3 snyk-pylock-test.py sample_requirements.txt```

## Generate HTML Report
The JSON output can be provided to the snyk-to-html utility by way of jq to produce an HTML report.  See [sample_results.html](https://github.com/snyk-tech-services/snyk-pylock-test/blob/master/sample_results.html) provided.  

To put it all together:

```python3 snyk-pylock-test.py sample_requirements.txt| jq '.issues' | snyk-to-html -o sample_results.html```

  Output:
  ```
        info: parsing as requirements file format
        Vulnerability snapshot saved at sample_results.html
  ```

## Todo
- Put JSON parsing inside the python script so ```jq``` is not required
- provide support for Pipfile.lock format files
- base64 encode API input for efficiency
