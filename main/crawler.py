import http.client
import requests
from requests.exceptions import ConnectionError
import urllib
import re
from urllib.parse import urljoin
from urllib3.exceptions import ProtocolError
from bs4 import BeautifulSoup
from requests_html import HTMLSession
from colorama import *
init(autoreset=True)

# Variables:
reset = Fore.RESET
red = Fore.RED
yellow = Fore.YELLOW
green = Fore.GREEN
magenta = Fore.MAGENTA
l_blue = Fore.LIGHTBLUE_EX


class Crawl:
    def __init__(self, url, cookies):
        self.url = url
        self.cookies = cookies
        self.r = requests.get(self.url, cookies=self.cookies)
        self.bs = BeautifulSoup(self.r.text, 'html.parser')
        self.session = HTMLSession
        self.parameters = {}
        self.total_form_fields = []
        self.total_input_tags = []
        self.total_hidden_input_tags = []
        self.textarea_tags = []
        self.paramkey = None
        self.keylist = []
        self.find_parameters()

    def find_parameters(self):
        new_url = urllib.parse.urlparse(self.url)  # Discovers scheme, netloc, path, params, query, fragment, etc.
        param_string = new_url.query
        self.parameters = dict(urllib.parse.parse_qsl(param_string))
        for self.paramkey in self.parameters:
            self.keylist.append(self.paramkey)
        self.find_form_fields()

    def find_form_fields(self):
        forms = (self.bs.find_all("form"))
        for form in forms:
            self.total_form_fields.append(str(form))
        input_tags = (self.bs.find_all("input"))
        textarea_tags = (self.bs.find_all("textarea"))
        self.find_input_fields(input_tags, textarea_tags)

    def find_input_fields(self, input_tags, textarea_tags):
        for input_tag in input_tags:
            self.total_input_tags.append(str(input_tag))
            # Filters out buttons and check boxes:
            self.total_input_tags = [x for x in self.total_input_tags if "hidden" not in x]
            self.total_input_tags = [x for x in self.total_input_tags if 'id="button"' not in x]
            self.total_input_tags = [x for x in self.total_input_tags if 'type="checkbox"' not in x]
            self.total_input_tags = [x for x in self.total_input_tags if 'type="submit"' not in x]
        for input_tag in input_tags:
            if re.search("hidden", str(input_tag)):
                self.total_hidden_input_tags.append(str(input_tag))
            else:
                pass
        for textarea_tag in textarea_tags:
            self.textarea_tags.append(str(textarea_tag))
        self.display_injection_points()

    def display_injection_points(self):
        print("-" * 80)
        print(yellow + "[+] Crawling for injection points on " + self.url + ":")
        print(yellow + "\n\t[-]" + reset + "Discovered " + green + str(len(self.total_input_tags)) + reset + " input field(s).")
        print(yellow + "\t[-]" + reset + "Discovered " + green + str(len(self.total_hidden_input_tags)) + reset + " hidden input field(s).")
        print(yellow + "\t[-]" + reset + "Discovered " + green + str(len(self.total_form_fields)) + reset + " form field(s).")
        print(yellow + "\t[-]" + reset + "Discovered " + green + str(len(self.parameters)) + reset + " form field(s).")
        if self.parameters:
            print(yellow + "\t[-]" + reset + "Discovered " + green + str(len(self.keylist)) + reset + " parameter(s).")
            for self.key in self.parameters:
                print(yellow + '\t\t[*]' + reset + "Discovered " + green + self.key + reset + " parameter")
        Links(self.url, self.cookies)


class Links:
    def __init__(self, url, cookies):
        self.url = url
        self.cookies = cookies
        self.session = HTMLSession()
        self.r = requests.get(self.url, cookies=self.cookies)
        self.page = self.r.text
        self.bs = BeautifulSoup(self.r.text, 'html.parser')
        self.hyperlinks = []
        self.unencrypted_hyperlinks = []
        self.total_sop_violations = []
        self.find_unencrypted_links()

    def find_unencrypted_links(self):
        """Displays all unencrypted links"""
        self.hyperlinks = []
        for link in self.bs.find_all('a', href=True):
            self.hyperlinks.append(str(link.get('href')))
        try:
            for link in self.hyperlinks:
                if link is None:
                    pass
                elif link.startswith('http:/'):
                    self.unencrypted_hyperlinks.append(link)
        except AttributeError:
            pass
        self.sop_violations()

    def sop_violations(self):
        """Displays all SOP violations"""
        www_link = False
        global www_url
        global dom_url

        # Identifies hyperlinks with "www" in them
        if '//www.' in self.url:
            www_link = True
            split_www_url = self.url.split('//www.')  # split 'www' from the url
            base_url = split_www_url[1]  # (e.g., 'www.google.com' changes to 'google.com')
            www_url = 'https://www.' + base_url  # (e.g., 'https://www.' + 'google.com')
            dom_url = 'https://' + base_url  # (e.g., 'https://' + 'google.com')
        else:
            pass

        #  Identifies clear SOP violations
        try:
            for link in self.hyperlinks:
                if link is None:
                    pass
                elif not link.startswith(self.url):
                    self.total_sop_violations.append(link)
        except AttributeError:
            pass

        if www_link is True:
            www_junk = (www_url, dom_url, '#', 'http:', '/', '\\')  # junk that isn't considered SOP violations
            for line in self.total_sop_violations[:]:  # for all elements in the sop array
                if line.startswith(www_junk):
                    self.total_sop_violations.remove(line)

        if www_link is False:
            split_domurl = self.url.split('https://')  # split 'www' from the url
            base_url = split_domurl[1]
            dom_url = 'https://' + base_url
            www_url = 'https://www.' + base_url
            dom_junk = (www_url, dom_url, '#', 'http:', '/', '\\')
            for line in self.total_sop_violations[:]:
                if line.startswith(dom_junk):
                    self.total_sop_violations.remove(line)
        self.display_hyperlink_info()

    def display_hyperlink_info(self):
        print('\n' + '-' * 80)
        print(yellow + '[+] Crawling for hyperlinks on ' + self.url + ':')
        print(yellow + '\n\t\t[-]' + reset + 'Discovered ' + green + str(len(self.hyperlinks)) + reset + ' hyperlinks.')
        print(yellow + '\t\t[-]' + reset + 'Discovered ' + green + str(len(self.unencrypted_hyperlinks)) + reset + ' unencrypted hyperlinks:')
        if self.unencrypted_hyperlinks:
            for line in self.unencrypted_hyperlinks:
                print(yellow + '\t\t\t[*]' + reset + line)  # display unencrypted links
        else:
            pass
        print(yellow + '\t\t[-]' + reset + 'Discovered ' + green + str(len(self.total_sop_violations)) + reset + ' SOP violations:')
        if self.total_sop_violations:
            for line in self.total_sop_violations:
                print(yellow + '\t\t\t[*]' + reset + line)
        else:
            pass
        SensitiveInfo(self.url, self.cookies)


class SensitiveInfo:
    def __init__(self, url, cookies):
        self.url = url
        self.cookies = cookies
        self.session = HTMLSession()
        self.r = requests.get(self.url, cookies=self.cookies)
        self.page = self.r.text
        self.bs = BeautifulSoup(self.r.text, 'html.parser')
        self.telephone_numbers = []
        self.ip_addresses = []
        self.email_addresses = []
        self.api_keys = []
        self.find_telephone_nums()

    def find_telephone_nums(self):
        self.telephone_numbers = re.findall('(\d{3}[-\.\s]??\d{3}[-\.\s]??\d{4}|\(\d{3}\)\s*\d{3}[-\.\s]??\d{4}|\d{3}[-\.\s]??\d{4})', self.r.text)
        self.find_ip_addresses()

    def find_ip_addresses(self):
        self.ip_addresses = re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', self.r.text)
        self.find_email_addresses()

    def find_email_addresses(self):
        self.email_addresses = re.findall(r'([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)', self.r.text)
        self.find_api_keys()

    def find_api_keys(self):
        self.api_keys = re.findall('(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])', self.r.text)
        self.api_keys = re.findall('(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])', self.r.text)
        self.display_sensitive_info()

    def display_sensitive_info(self):
        print('\n' + '-' * 80)
        print(yellow + '[+] Displaying possible sensitive info on ' + self.url + ':')
        print(yellow + "\n\t[-]" + reset + "Discovered " + green + str(len(self.telephone_numbers)) + reset + " possible telephone number(s).")
        if self.telephone_numbers:
            for line in self.telephone_numbers:
                print(yellow + '\t\t[*]' + reset + line)
        else:
            pass
        print(yellow + "\t[-]" + reset + "Discovered " + green + str(len(self.ip_addresses)) + reset + " possible IP address(es).")
        if self.ip_addresses:
            for line in self.ip_addresses:
                print(yellow + '\t\t[*]' + reset + line)
        else:
            pass
        print(yellow + "\t[-]" + reset + "Discovered " + green + str(len(self.email_addresses)) + reset + " possible E-mail address(es).")
        if self.email_addresses:
            for line in self.email_addresses:
                print(yellow + '\t\t[*]' + reset + line)
        else:
            pass
        print(yellow + "\t[-]" + reset + "Discovered " + green + str(len(self.api_keys)) + reset + " possible API key(s).")
        if self.api_keys:
            for line in self.api_keys:
                print(yellow + '\t\t[*]' + reset + line)
        else:
            pass
        InspectHeaders(self.url, self.cookies)


class InspectHeaders:
    """Inspect server headers for vulnerabilities"""
    def __init__(self, url, cookies):
        self.url = url
        self.cookies = cookies
        self.session = HTMLSession()
        self.r = requests.get(self.url, cookies=self.cookies)
        self.headers = []
        self.headers_inspect()

    def headers_inspect(self):
        print('-' * 80)
        print(yellow + '[+] Crawling server headers on ' + self.url + ':')
        for header in self.r.headers:
            self.headers.append(header.lower())
        for header in self.r.headers:
            print('\t' + header + ' : ' + self.r.headers[header])
        self.headers_eval()

    def headers_eval(self):
        print(yellow + "\n\t[-]" + reset + "Potential security issues:")
        if 'http-only' or 'httponly' not in self.headers:
            print(yellow + '\t\t[*]HTTPOnly flag is disabled.')
        if 'strict-transport-security' not in self.headers:
            print(yellow + '\t\t[*]HTTP Strict-Transport-Security (HSTS) is disabled.')
        if "x-frame-options" not in self.headers:
            print(yellow + "\t\t[*]X-Frame-Options is disabled.")
        if "x-xss-protection" not in self.headers:
            print(yellow + "\t\t[*]X-XSS-Protection is disabled.")
        if "x-content-type-options" not in self.headers:
            print(yellow + "\t\t[*]X-Content-Type-Options is disabled.")
        if "content-security-policy" not in self.headers:
            print(yellow + "\t\t[*]Content-Security-Policy is disabled.")
        if "set-cookie" not in self.headers:
            print(yellow + "\t\t[*]Set-Cookie is disabled.")
        if "x-powered-by" in self.headers:
            print(yellow + "\t\t[*]X-Powered-By Header is enabled.")
        else:
            pass
        Dirs(self.url, self.cookies)


class Dirs:
    def __init__(self, url, cookies):
        self.url = url
        self.cookies = cookies
        self.session = HTMLSession()
        self.r = requests.get(self.url, cookies=self.cookies)
        self.directory_disc()

    def directory_disc(self):
        print('-' * 80)
        print(yellow + '[+] Crawling directories on ' + self.url + ':\n')
        with open("wordlists/common-directories.txt", "r") as f:
            for directory in f.readlines():
                directory = directory.strip('\n')
                # can't use default headers
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.119 Safari/537.36"}
                brute = requests.get(self.url + "/" + directory, headers=headers)
                try:
                    if brute.status_code == 200:
                        print(yellow + "\t[-]" + reset + directory + ' ' + green + str(brute))
                    else:
                        print(yellow + "\t[-]" + reset + directory + ' ' + str(brute))
                except ConnectionError:
                    pass
                except ProtocolError:
                    pass
                except http.client.RemoteDisconnected:
                    pass
        exit()
