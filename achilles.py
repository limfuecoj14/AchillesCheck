#This is a self made project that checks URLS for vulnerabilities
#with regards to form, comments, and passwords. It will then go
#through the website HTML to check for issues, then finally
#it prints a report to a file. I do not have a standard config file
#so the recommended run is 'achilles.py <YOUR HTTP/HTTPS WEBSITE HERE> -o report.txt

#!/usr/bin/env python3
# using personal URL  https://freecyclesu.azurewebsites.net
import argparse
import requests
import validators
# import yml
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from bs4 import Comment

parser = argparse.ArgumentParser(description='The Achilles HTML Vulnerability Analyzer Version 1.0')

parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
parser.add_argument('url', type=str, help="The URL of the HTML to analyze")
parser.add_argument('--config', help='Path to configuration file')

parser.add_argument('-o', '--output', help='Report file output path')

args = parser.parse_args()

config = {'forms': True, 'comments': True, 'passwords': True}

##TODO: create a config yml for this project and figure it out
# I believe I have a sort of work around since yml is just a text file BUT I don't have the right yaml package
# if(args.config):
# print('Using config file: ' + args.config)
# config_file = open(args.config, 'r')
# config_from_file = yml.load(config_file)
# if(config_from_file):
#   config= config_from_file
#   config= {**config, **config_from_file}

report = ''
url = args.url

if (validators.url(url)):
    result_html = requests.get(url).text
    parsed_html = BeautifulSoup(result_html, 'html.parser')

    forms = parsed_html.find_all('form')
    comments = parsed_html.find_all(string=lambda text: isinstance(text, Comment))
    password_inputs = parsed_html.find_all('input', {'name': 'password'})

    for form in forms:
        if ((form.get('action'.find('https') < 0) and (urlparse(url).scheme != 'https'))):
            report += ' Form Issue: Insecure form found in document\n'

    for comment in comments:
        if (comment.find('key: ') > -1):
            report += 'Comment Issue: Key is found in the HTML'

    for password_input in password_inputs:
        if (password_input.get('type') != 'password'):
            report += 'Input Issue: Plaintext password input found. Please change to password type input\n'
else:
    print('INVALID URL. Please include full URL including scheme.')

if (report == ''):
    print('Nice job! Your HTML document is secure!')
else:
    header = 'Vulnerability Report is as follows:\n'
    header += '==================================\n\n'
    report = header + report
    print(report)

if args.output:
    f = open(args.output, 'w')
    f.write(report)
    f.close()
    print('report saved to: ' + args.output)
