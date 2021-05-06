from main.validation import ValidateURL
from main.crawler import Crawl
import pyfiglet
from colorama import *
init(autoreset=True)

# Variables:
reset = Fore.RESET
red = Fore.RED
yellow = Fore.YELLOW
green = Fore.GREEN
magenta = Fore.MAGENTA


class Banner:
    def __init__(self):
        self.banner()

    def banner(self):
        ascii_banner = pyfiglet.figlet_format("WEB-CRAWL3R")
        print(magenta + ascii_banner)


class Menu:
    def __init__(self):
        self.url = None
        self.enter_url()

    def enter_url(self):
        print("-" * 80)
        self.url = input(yellow + "[+]" + reset + "Enter a web page URL to crawl: ")
        if len(self.url) == 0:
            print(red + "\nYou didn't enter a URL")
            self.enter_url()
        ValidateURL(self.url)
        Cookies(self.url)


class Cookies:
    def __init__(self, url):
        self.url = url
        self.cookies = None
        self.cookie_grab()

    def cookie_grab(self):
        ans = input("\nAdd a cookie with the request? [y/n]: ")
        if ans.lower() == "n":
            self.cookies = None
            Crawl(self.url, self.cookies)
        elif ans.lower() == "y":
            print(yellow + '\n[+] Returning stored cookie information for ' + self.url + ': \n')


b = Banner()
m = Menu()