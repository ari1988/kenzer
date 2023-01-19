# imports
import zulip
import time
from datetime import datetime
import os
import sys
from chatterbot import ChatBot
from chatterbot.trainers import ChatterBotCorpusTrainer
from configparser import ConfigParser
import validators
import tldextract
import ipaddress
import secrets
import string

# core modules
from modules import enumerator
from modules import scanner
from modules import monitor

# colors
BLUE = '\033[94m'
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CLEAR = '\x1b[0m'

# configs
try:
    conf = "configs/kenzer.conf"
    config = ConfigParser()
    with open(conf) as f:
        config.read_file(f, conf)
    _BotMail = config.get("kenzer", "email")
    _Site = config.get("kenzer", "site")
    _APIKey = config.get("kenzer", "key")
    _uploads = config.get("kenzer", "uploads")
    _subscribe = config.get("kenzer", "subscribe")
    _kenzer = config.get("kenzer", "path")
    _logging = config.get("kenzer", "logging")
    _splitting = config.get("kenzer", "splitting")
    _sync = config.get("kenzer", "syncing")
    _kenzerdb = config.get("kenzerdb", "path")
    _github = config.get("kenzerdb", "token")
    _repo = config.get("kenzerdb", "repo")
    _user = config.get("kenzerdb", "user")
    _home = config.get("env", "home")
    _greynoise = config.get("env", "greynoise")
    _xsshunter = config.get("env", "xsshunter")
    _shodan = config.get("env", "shodan")
    _whoisxmlapi = config.get("env", "whoisxmlapi")
    _viewdns = config.get("env", "viewdns")
    _netlas = config.get("env", "netlas")
    _waf = config.get("env", "avoid-waf")
    _enablezap = config.get("env", "enable-zap")
    _ish = config.get("env", "interactsh-server")+"|"+config.get("env", "interactsh-token")
    _proxyurl = config.get("env", "proxy-url")
    if "http" not in _ish:
        _ish=""
    _eproxy = False
    if "http" not in _proxyurl and "socks" not in _proxyurl
        _proxyurl=""
    else:
        os.environ["http_proxy"] = _proxyurl
        os.environ["https_proxy"] = _proxyurl
        _eproxy = True
    _delegates = []
    os.chdir(_kenzer)
    os.environ["HOME"] = _home
    if(os.path.exists(_kenzerdb) == False):
        os.system("mkdir "+_kenzerdb)
    _zap = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for i in range(12))
    if _enablezap=="True":
        os.system("zap.sh -daemon -port 8077 -config api.key={0} &".format(_zap))
        print(YELLOW+"[*] started ZAP"+CLEAR)
    if len(_netlas)>0:
        os.system("netlas savekey "+_netlas)
except Exception as exception:
    print(exception.__class__.__name__ + ": " + str(exception))
    sys.exit(RED+"[!] invalid configurations"+CLEAR)

# kenzer


class Kenzer(object):

    # initializations
    def __init__(self):
        print(BLUE+"KENZER[3.67] by ARPSyndicate"+CLEAR)
        print(YELLOW+"automated web assets enumeration & scanning"+CLEAR)
        self.client = zulip.Client(email=_BotMail, site=_Site, api_key=_APIKey)
        self.upload = False
        if _subscribe == "True":
            self.subscribe()
            print(YELLOW+"[*] subscribed all streams"+CLEAR)
        if _uploads == "True":
            self.upload = True
            print(YELLOW+"[*] enabled uploads"+CLEAR)
        print(YELLOW+"[*] training chatterbot"+CLEAR)
        self.chatbot = ChatBot("Kenzer")
        self.trainer = ChatterBotCorpusTrainer(self.chatbot)
        time.sleep(1)
        self.trainer.train("chatterbot.corpus.english")
        time.sleep(1)
        self.modules = ["monitor", "program", "blacklist", "whitelist", "subenum", "repenum", "repoenum", "wafscan", "keysenum", "webenum", "servenum", "urlheadenum", "headenum", "socenum", "conenum", "dnsenum", "portenum", "asnenum", "urlenum", "favscan",
                        "bakscan", "cscan", "urlscan", "idscan", "subscan", "disseminate", "cvescan", "vulnscan", "reposcan", "portscan", "shodscan", "appscan", "buckscan", "vizscan", "enum", "scan", "recon", "hunt", "sync", "freaker"]
        print(YELLOW+"[*] KENZER is online"+CLEAR)
        print(
            YELLOW+"[*] {0} modules up & running".format(len(self.modules))+CLEAR)

    # subscribes to all streams
    def subscribe(self):
        try:
            json = self.client.get_streams()["streams"]
            streams = [{"name": stream["name"]} for stream in json]
            self.client.add_subscriptions(streams)
        except:
            print(RED+"[!] an exception occurred.... retrying...."+CLEAR)
            self.subscribe()

    # manual
    def man(self):
        message = "**KENZER[3.67]**\n"
        message += "**KENZER modules**\n"
        message += "`blacklist <target>,<regex>` - initializes & removes blacklisted targets\n"
        message += "`whitelist <target>,<regex>` - initializes & keeps only whitelisted targets\n"
        message += "`program <target>,[<name>][<meta>][<link>]` - initializes the program to which target belongs\n"
        message += "`subenum[-<mode>[active/passive/fast (default=all)]] <target>` - enumerates subdomains\n"
        message += "`repenum <target>` - enumerates reputation of subdomains\n"
        message += "`repoenum <target>` - enumerates github repositories\n"
        message += "`portenum[-<mode>[100/1000/full/fast (default=1000)]] <target>` - enumerates open ports\n"
        message += "`servenum <target>` - enumerates services\n"
        message += "`webenum <target>` - enumerates webservers\n"
        message += "`headenum <target>` - enumerates additional info from webservers\n"
        message += "`urlheadenum <target>` - enumerates additional info from urls\n"
        message += "`asnenum <target>` - enumerates asn records\n"
        message += "`dnsenum <target>` - enumerates dns records\n"
        message += "`conenum <target>` - enumerates hidden files & directories\n"
        message += "`urlenum[-<mode>[active/passive (default=all)]] <target>` - enumerates urls\n"
        message += "`socenum <target>` - enumerates social media accounts\n"
        message += "`keysenum <target>` - enumerates sensitive api keys\n"
        message += "`subscan[-<mode>[web/dns (default=all)]] <target>` - hunts for subdomain takeovers\n"
        message += "`urlscan[-<mode>[cmdi/crlf/redirect/sqli/ssrf/ssti/xss (default=all)]] <target>` - hunts for vulnerabilities in URL parameters\n"
        message += "`reposcan <target>` - scans github repositories for api key leaks\n"
        message += "`wafscan <target>` - scans for firewalls\n"
        message += "`bakscan <target>` - scans for backup files\n"
        message += "`cscan[-<severity>[critical/high/medium/low/info/workflow (default=all)]] <target>` - scan with customized templates\n"
        message += "`cvescan[-<severity>[critical/high/medium/low/info/workflow (default=all)]] <target>` - hunts for CVEs\n"
        message += "`vulnscan[-<severity>[critical/high/medium/low/info/workflow (default=all)]] <target>` - hunts for other common vulnerabilities\n"
        message += "`idscan[-<severity>[critical/high/medium/low/info/workflow (default=all)]] <target>` - identifies applications running on webservers\n"
        message += "`portscan <target>` - scans open ports (nmap)(slow)\n"
        message += "`shodscan <target>` - scans open ports (shodan)(fast)\n"
        message += "`xssscan <target>` - scans for xss vulnerabilities\n"
        message += "`appscan <target>` - scans for webapp vulnerabilities\n"
        message += "`buckscan <target>` - hunts for unreferenced aws s3 buckets\n"
        message += "`favscan <target>` - fingerprints webservers using favicon\n"
        message += "`vizscan[-<mode>[web/repo (default=web)]] <target>` - screenshots websites & repositories\n"
        message += "`disseminate <command> <target>` - splits & distributes input over multiple bots\n"
        message += "`enum <target>` - runs all enumerator modules\n"
        message += "`scan <target>` - runs all scanner modules\n"
        message += "`recon <target>` - runs all modules\n"
        message += "`hunt <target>` - runs your custom workflow\n"
        message += "`upload` - switches upload functionality\n"
        message += "`waf` - switches waf avoid functionality\n"
        message += "`proxy` - switches proxy functionality\n"
        message += "`upgrade` - upgrades kenzer to latest version\n"
        message += "`monitor <target>` - monitors ct logs for new subdomains\n"
        message += "`monitor normalize` - normalizes the enumerations from ct logs\n"
        message += "`monitor db` - monitors ct logs for domains in summary/domain.txt\n"
        message += "`monitor autohunt <frequency(default=5)>` - starts automated hunt while monitoring\n"
        message += "`sync[-pull]` - synchronizes the local kenzerdb with github\n"
        message += "`freaker <module> [<target>]` - runs freaker module\n"
        message += "`kenzer <module>` - runs a specific module\n"
        message += "`kenzer man` - shows this manual\n"
        message += "multiple commands must be separated by comma(,)\n"
        message += "or you can just interact with chatterbot\n"
        self.sendMessage(message)
        return

    # sends messages
    def sendMessage(self, message):
        time.sleep(1)
        if self.type == "private":
            self.client.send_message({
                "type": self.type,
                "to": self.sender_email,
                "content": message
            })
        else:
            self.client.send_message({
                "type": self.type,
                "subject": self.subject,
                "to": self.display_recipient,
                "content": message
            })
        time.sleep(1)
        return

    # uploads output
    def uploader(self, domain, raw):
        global _kenzerdb
        global _Site
        org = domain
        data = _kenzerdb+org+"/"+raw
        if(os.path.exists(data) == False):
            return
        with open(data, 'rb') as fp:
            uploaded = self.client.call_endpoint(
                'user_uploads',
                method='POST',
                files=[fp],
            )
        self.sendMessage("{0}/{1} : {3}{2}".format(org,
                                                   raw, uploaded['uri'], _Site))
        return

    # removes log files
    def remlog(self):
        os.system("rm {0}*/*.log*".format(_kenzerdb))
        os.system("rm {0}*/*.old*".format(_kenzerdb))
        os.system("rm {0}*/*.csv*".format(_kenzerdb))
        os.system(
            "rm -r {0}*/nuclei {0}*/jaeles {0}*/passive-jaeles {0}*/nxscan {0}*/gocrawler {0}*/reposcan".format(_kenzerdb))
        os.system("find {0} -type f -empty -delete".format(_kenzerdb))
        return

    # splits .kenz files
    def splitkenz(self, cont):
        dtype = False
        if validators.domain(cont.lower()) == True or cont.lower() == "monitor":
            dtype = True
        else:
            try:
                ipaddress.ip_network(cont.replace("#", "/"))
            except ValueError:
                return
        self.enum = enumerator.Enumerator(
            cont.lower(), _kenzerdb, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), dtype)
        self.enum.splitkenz()
        return

    # merges .kenz files
    def mergekenz(self, cont):
        dtype = False
        if validators.domain(cont.lower()) == True or cont.lower() == "monitor":
            dtype = True
        else:
            try:
                ipaddress.ip_network(cont.replace("#", "/"))
            except ValueError:
                return
        self.enum = enumerator.Enumerator(
            cont.lower(), _kenzerdb, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), dtype)
        self.enum.mergekenz()
        return

    # merges .split files
    def mergesplit(self, cont):
        dtype = False
        if validators.domain(cont.lower()) == True or cont.lower() == "monitor":
            dtype = True
        else:
            try:
                ipaddress.ip_network(cont.replace("#", "/"))
            except ValueError:
                return
        self.enum = enumerator.Enumerator(
            cont.lower(), _kenzerdb, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), dtype)
        self.enum.mergesplit()
        return

    # monitors ct logs
    def monitor(self):
        self.sendMessage("[monitor - running in background]")
        self.monitor = monitor.Monitor(_kenzerdb, " ".join(self.content[2:]))
        self.assemble_delegates()
        self.monitor.certex()
        self.monitor.subfinder()
        return

    # monitors ct logs for domains in summary/domain.txt
    def monitor_kenzerdb(self):
        domfile = _kenzerdb+"../summary/domain.txt"
        with open(domfile) as f:
            line = len(f.readlines())
        self.sendMessage("[monitor - running in background]")
        self.monitor = monitor.Monitor(_kenzerdb)
        self.assemble_delegates()
        self.monitor.certex()
        self.monitor.subfinder()
        return

    # starts automated hunt while monitoring
    def monitor_autohunt(self, freq=5):
        i = 1
        while i <= freq:
            self.monitor = monitor.Monitor(_kenzerdb)
            self.content = "**{0}** hunt monitor".format(
                _BotMail.split("@")[0]).split()
            self.hunt()
            self.monitor.normalize()
            self.sendMessage(
                "[autohunt - ({0})]".format("{0}/{1}".format(i,freq)))
            if _sync == "True":
                self.sync()
            i = i+1
        return

    # normalizes enumerations from ct logs
    def normalize(self):
        self.monitor = monitor.Monitor(_kenzerdb, " ".join(self.content[2:]))
        self.monitor.normalize()
        self.sendMessage("[normalized]")
        return

    # initializes the program to which target belongs
    def program(self):
        for i in range(2, len(self.content)):
            dtype = False
            domain = self.content[i].split(",")[0].lower()
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(domain)
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            self.sendMessage(
                "[program - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain))
            self.enum = enumerator.Enumerator(
                domain, _kenzerdb, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), dtype)
            message = self.enum.program(
                self.content[i].split(",")[1])
            self.sendMessage(
                "[program - ({0}) - {1}] {2}".format("{0}/{1}".format((i-1),(len(self.content)-2)), message, domain))
            if self.upload:
                file = "program.kenz"
                self.uploader(self.content[i], file)
        return

    # initializes & removes blacklisted targets
    def blacklist(self):
        for i in range(2, len(self.content)):
            dtype = False
            domain = self.content[i].split(",")[0].lower()
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(domain)
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(domain))
                    continue
            self.sendMessage(
                "[blacklist - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain))
            self.enum = enumerator.Enumerator(
                domain, _kenzerdb, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), dtype)
            message = self.enum.blacklist(
                self.content[i].split(",")[1])
            self.sendMessage(
                "[blacklist - ({0}) - {1}] {2}".format("{0}/{1}".format((i-1),(len(self.content)-2)), message, domain))
            if self.upload:
                file = "blacklist.kenz"
                self.uploader(self.content[i], file)
        return

    # initializes & keeps only whitelisted targets
    def whitelist(self):
        for i in range(2, len(self.content)):
            dtype = False
            domain = self.content[i].split(",")[0].lower()
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(domain)
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            self.sendMessage(
                "[whitelist - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain))
            self.enum = enumerator.Enumerator(
                domain, _kenzerdb, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), dtype)
            message = self.enum.whitelist(
                self.content[i].split(",")[1])
            self.sendMessage(
                "[whitelist - ({0}) - {1}] {2}".format("{0}/{1}".format((i-1),(len(self.content)-2)), message, domain))
            if self.upload:
                file = "whitelist.kenz"
                self.uploader(self.content[i], file)
        return

    # enumerates subdomains
    def subenum(self, mode=""):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            display = ""
            if(len(mode) > 0):
                display = "({0})".format(mode)
            self.sendMessage(
                "[subenum{2} - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain,display))
            if domain == "monitor":
                self.monitor = monitor.Monitor(_kenzerdb)
                self.monitor.initialize()
                message = self.monitor.subenum()
            else:
                self.enum = enumerator.Enumerator(
                    domain, _kenzerdb, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), dtype)

                message = self.enum.subenum(_github, _shodan, _viewdns, _whoisxmlapi, mode)
            self.sendMessage("[subenum{3} - ({0}) - {1}] {2}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), message, domain, display))
            if self.upload:
                file = "subenum.kenz"
                self.uploader(self.content[i], file)
        return

    # probes services from enumerated ports
    def servenum(self):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            self.sendMessage(
                "[servenum - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain))
            self.enum = enumerator.Enumerator(
                domain, _kenzerdb, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), dtype)
            message = self.enum.servenum()
            self.sendMessage("[servenum - ({0}) - {1}] {2}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), message, domain))
            if self.upload:
                file = "servenum.kenz"
                self.uploader(self.content[i], file)
        return

    # probes web servers from enumerated ports
    def webenum(self):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            self.sendMessage(
                "[webenum - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain))
            self.enum = enumerator.Enumerator(
                domain, _kenzerdb, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), dtype)
            message = self.enum.webenum()
            self.sendMessage("[webenum - ({0}) - {1}] {2}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), message, domain))
            if self.upload:
                file = "webenum.kenz"
                self.uploader(self.content[i], file)
        return

    # enumerates additional info from webservers
    def headenum(self):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            self.sendMessage(
                "[headenum - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain))
            self.enum = enumerator.Enumerator(
                domain, _kenzerdb, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), dtype)
            message = self.enum.headenum()
            self.sendMessage("[headenum - ({0}) - {1}] {2}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), message, domain))
            if self.upload:
                file = "headenum.kenz"
                self.uploader(self.content[i], file)
        return

    # scans for firewalls
    def wafscan(self):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            self.sendMessage(
                "[wafscan - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain))
            self.scan = scanner.Scanner(
                domain, _kenzerdb, dtype, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), _waf)
            message = self.scan.wafscan()
            self.sendMessage("[wafscan - ({0}) - {1}] {2}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), message, domain))
            if self.upload:
                file = "wafscan.kenz"
                self.uploader(self.content[i], file)
        return

    # enumerates additional info from urls
    def urlheadenum(self):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = True
            if(validators.domain(domain) != True):
                self.sendMessage("[invalid] {0}".format(
                    domain))
                continue
            self.sendMessage("[urlheadenum - ({0})] {1}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), domain))
            self.enum = enumerator.Enumerator(
                domain, _kenzerdb, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), dtype)
            message = self.enum.urlheadenum()
            self.sendMessage("[urlheadenum - ({0}) - {1}] {2}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), message, domain))
            if self.upload:
                file = "urlheadenum.kenz"
                self.uploader(self.content[i], file)
        return

    # enumerates dns records
    def dnsenum(self):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            self.sendMessage(
                "[dnsenum - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain))
            self.enum = enumerator.Enumerator(
                domain, _kenzerdb, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), dtype)
            message = self.enum.dnsenum()
            self.sendMessage("[dnsenum - ({0}) - {1}] {2}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), message, domain))
            if self.upload:
                file = "dnsenum.kenz"
                self.uploader(self.content[i], file)
        return

    # enumerates hidden files & directories
    def conenum(self):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            self.sendMessage(
                "[conenum - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain))
            self.enum = enumerator.Enumerator(
                domain, _kenzerdb, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), dtype)
            message = self.enum.conenum()
            self.sendMessage(
                "[conenum - ({0}) - {1}] {2}".format("{0}/{1}".format((i-1),(len(self.content)-2)), message, domain))
            if self.upload:
                file = "conenum.kenz"
                self.uploader(self.content[i], file)
        return

    # enumerates asn for enumerated subdomains
    def asnenum(self):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            self.sendMessage(
                "[asnenum - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain))
            self.enum = enumerator.Enumerator(
                domain, _kenzerdb, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), dtype)
            message = self.enum.asnenum()
            self.sendMessage("[asnenum - ({0}) - {1}] {2}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), message, domain))
            if self.upload:
                file = "asnenum.kenz"
                self.uploader(self.content[i], file)
        return

    # enumerates open ports
    def portenum(self, mode=""):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            display = ""
            if(len(mode) > 0):
                display = "({0})".format(mode)
            self.sendMessage(
                "[portenum{2} - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain, display))
            self.enum = enumerator.Enumerator(
                domain, _kenzerdb, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), dtype)
            message = self.enum.portenum(mode)
            self.sendMessage("[portenum{3} - ({0}) - {1}] {2}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), message, domain, display))
            if self.upload:
                file = "portenum.kenz"
                self.uploader(self.content[i], file)
        return

    # enumerates reputation of subdomains
    def repenum(self):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            self.sendMessage(
                "[repenum - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain))
            self.enum = enumerator.Enumerator(
                domain, _kenzerdb, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), dtype)
            message = self.enum.repenum(_greynoise)
            self.sendMessage("[repenum - ({0}) - {1}] {2}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), message, domain))
            if self.upload:
                file = "repenum.kenz"
                self.uploader(self.content[i], file)
        return

    # enumerates github repositories
    def repoenum(self):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = True
            if(validators.domain(domain) != True):
                self.sendMessage("[invalid] {0}".format(
                    domain))
                continue
            self.sendMessage(
                "[repoenum - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain))
            self.enum = enumerator.Enumerator(
                domain, _kenzerdb, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), dtype)
            message = self.enum.repoenum(_github)
            self.sendMessage("[repoenum - ({0}) - {1}] {2}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), message, domain))
            if self.upload:
                file = "repoenum.kenz"
                self.uploader(self.content[i], file)
        return


    # enumerates urls
    def urlenum(self, mode=""):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            display = ""
            if(len(mode) > 0):
                display = "({0})".format(mode)
            self.sendMessage(
                "[urlenum{2} - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain,display))
            self.enum = enumerator.Enumerator(
                domain, _kenzerdb, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), dtype)
            message = self.enum.urlenum(_github, mode)
            self.sendMessage("[urlenum{3} - ({0}) - {1}] {2}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), message, domain,display))
            if self.upload:
                file = "urlenum.kenz"
                self.uploader(self.content[i], file)
        return

    # hunts for subdomain takeovers
    def subscan(self):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            self.sendMessage(
                "[subscan - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain))
            self.scan = scanner.Scanner(
                domain, _kenzerdb, dtype, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), _waf)
            message = self.scan.subscan(_ish)
            self.sendMessage("[subscan - ({0}) - {1}] {2}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), message, domain))
            if self.upload:
                file = "subscan.kenz"
                self.uploader(self.content[i], file)
        return

    # enumerates social media accounts
    def socenum(self):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            self.sendMessage(
                "[socenum - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain))
            self.enum = enumerator.Enumerator(
                domain, _kenzerdb, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), dtype)
            message = self.enum.socenum()
            self.sendMessage("[socenum - ({0}) - {1}] {2}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), message, domain))
            if self.upload:
                file = "socenum.kenz"
                self.uploader(self.content[i], file)
        return

    # enumerates sensitive api keys
    def keysenum(self):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            self.sendMessage(
                "[keysenum - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain))
            self.enum = enumerator.Enumerator(
                domain, _kenzerdb, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), dtype)
            message = self.enum.keysenum()
            self.sendMessage("[keysenum - ({0}) - {1}] {2}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), message, domain))
            if self.upload:
                file = "keysenum.kenz"
                self.uploader(self.content[i], file)
        return

    # hunts for vulnerabilities in URL parameters
    def urlscan(self, severity=""):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            display = ""
            if(len(severity) > 0):
                display = "({0})".format(severity)
            self.sendMessage("[urlscan{2} - ({0})] {1}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), domain, display))
            self.scan = scanner.Scanner(
                domain, _kenzerdb, dtype, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), _waf, severity)
            message = self.scan.urlscan(_ish)
            self.sendMessage("[urlscan{3} - ({0}) - {1}] {2}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), message, domain, display))
            if self.upload:
                file = "urlscan.kenz"
                self.uploader(self.content[i], file)
        return

    # scans with customized templates
    def cscan(self, severity=""):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            display = ""
            if(len(severity) > 0):
                display = "({0})".format(severity)
            self.sendMessage("[cscan{2} - ({0})] {1}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), domain, display))
            self.scan = scanner.Scanner(
                domain, _kenzerdb, dtype, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), _waf, severity)
            message = self.scan.cscan(_ish)
            self.sendMessage("[cscan{3} - ({0}) - {1}] {2}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), message, domain, display))
            if self.upload:
                file = "cscan.kenz"
                self.uploader(self.content[i], file)
        return

    # hunts for CVEs
    def cvescan(self, severity=""):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            display = ""
            if(len(severity) > 0):
                display = "({0})".format(severity)
            self.sendMessage("[cvescan{2} - ({0})] {1}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), domain, display))
            self.scan = scanner.Scanner(
                domain, _kenzerdb, dtype, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), _waf, severity)
            message = self.scan.cvescan(_ish)
            self.sendMessage("[cvescan{3} - ({0}) - {1}] {2}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), message, domain, display))
            if self.upload:
                file = "cvescan.kenz"
                self.uploader(self.content[i], file)
        return

    # hunts for other common vulnerabilities
    def vulnscan(self, severity=""):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            display = ""
            if(len(severity) > 0):
                display = "({0})".format(severity)
            self.sendMessage("[vulnscan{2} - ({0})] {1}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), domain, display))
            self.scan = scanner.Scanner(
                domain, _kenzerdb, dtype, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), _waf, severity)
            message = self.scan.vulnscan(_ish)
            self.sendMessage("[vulnscan{3} - ({0}) - {1}] {2}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), message, domain, display))
            if self.upload:
                file = "vulnscan.kenz"
                self.uploader(self.content[i], file)
        return

    # scans open ports (shodan)(fast)
    def shodscan(self):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            self.sendMessage(
                "[shodscan - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain))
            self.scan = scanner.Scanner(
                domain, _kenzerdb, dtype, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), _waf)
            message = self.scan.shodscan()
            self.sendMessage(
                "[shodscan - ({0}) {2}] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain, message))
            if self.upload:
                file = "shodscan.kenz"
                self.uploader(self.content[i], file)
        return
    
    # scans for backup files
    def bakscan(self):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            self.sendMessage(
                "[bakscan - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain))
            self.scan = scanner.Scanner(
                domain, _kenzerdb, dtype, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), _waf)
            message = self.scan.bakscan()
            self.sendMessage(
                "[bakscan - ({0}) {2}] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain, message))
            if self.upload:
                file = "bakscan.kenz"
                self.uploader(self.content[i], file)
        return
        
    # scans open ports (nmap)(slow)
    def portscan(self):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True:
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            self.sendMessage(
                "[portscan - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain))
            self.scan = scanner.Scanner(
                domain, _kenzerdb, dtype, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), _waf)
            message = self.scan.portscan()
            self.sendMessage(
                "[portscan - ({0}) {2}] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain, message))
            if self.upload:
                file = "portscan.kenz"
                self.uploader(self.content[i], file)
        return

    # scans github repositories for api key leaks
    def reposcan(self):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = True
            if(validators.domain(domain) != True):
                self.sendMessage("[invalid] {0}".format(
                    domain))
                continue
            display = ""
            self.sendMessage("[reposcan - ({0})] {1}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), domain))
            self.scan = scanner.Scanner(
                domain, _kenzerdb, dtype, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), _waf)
            message = self.scan.reposcan()
            self.sendMessage("[reposcan - ({0}) - {1}] {2}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), message, domain))
            if self.upload:
                file = "reposcan.kenz"
                self.uploader(self.content[i], file)
        return

    # hunts for subdomain takeovers
    def buckscan(self):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            self.sendMessage(
                "[buckscan - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain))
            self.scan = scanner.Scanner(
                domain, _kenzerdb, dtype, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), _waf)
            message = self.scan.buckscan()
            self.sendMessage("[buckscan - ({0}) - {1}] {2}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), message, domain))
            if self.upload:
                file = "buckscan.kenz"
                self.uploader(self.content[i], file)
        return

    # fingerprints servers using favicons
    def favscan(self):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            self.sendMessage(
                "[favscan - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain))
            self.scan = scanner.Scanner(
                domain, _kenzerdb, dtype, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), _waf)
            message = self.scan.favscan()
            self.sendMessage("[favscan - ({0}) - {1}] {2}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), message, domain))
            if self.upload:
                file = "favscan.kenz"
                self.uploader(self.content[i], file)
        return

    # scans for xss vulnerabilities
    def xssscan(self, blind=_xsshunter):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            self.sendMessage(
                "[xssscan - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain))
            self.scan = scanner.Scanner(
                domain, _kenzerdb, dtype, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), _waf)
            message = self.scan.xssscan(blind)
            self.sendMessage("[xssscan - ({0}) - {1}] {2}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), message, domain))
            if self.upload:
                file = "xssscan.kenz"
                self.uploader(self.content[i], file)
        return

    # scans for webapp vulnerabilities
    def appscan(self, zap=_zap):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True:
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            self.sendMessage(
                "[appscan - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain))
            self.scan = scanner.Scanner(
                domain, _kenzerdb, dtype, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), _waf)
            message = self.scan.appscan(zap)
            self.sendMessage("[appscan - ({0}) - {1}] {2}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), message, domain))
            if self.upload:
                file = "appscan.kenz"
                self.uploader(self.content[i], file)
        return


    # identifies applications running on webservers
    def idscan(self, severity=""):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            display = ""
            if(len(severity) > 0):
                display = "({0})".format(severity)
            self.sendMessage("[idscan{2} - ({0})] {1}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), domain, display))
            self.scan = scanner.Scanner(
                domain, _kenzerdb, dtype, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), _waf, severity)
            message = self.scan.idscan(_ish)
            self.sendMessage("[idscan{3} - ({0}) - {1}] {2}".format(
                "{0}/{1}".format((i-1),(len(self.content)-2)), message, domain, display))
            if self.upload:
                file = "idscan.kenz"
                self.uploader(self.content[i], file)
        return

    # screenshots websites & repositories
    def vizscan(self, mode=""):
        for i in range(2, len(self.content)):
            domain = self.content[i].lower()
            dtype = False
            if validators.domain(domain) == True or (domain == "monitor" and mode!="repo"):
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        domain))
                    continue
            display = ""
            if(len(mode) > 0):
                display = "({0})".format(mode)
            self.sendMessage(
                "[vizscan{2} - ({0})] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain, display))
            self.scan = scanner.Scanner(
                domain, _kenzerdb, dtype, _kenzer, _BotMail.split('@')[0].replace("-bot", ""), _waf)
            message = self.scan.vizscan(mode)
            self.sendMessage(
                "[vizscan{3} - ({0}) - {2}] {1}".format("{0}/{1}".format((i-1),(len(self.content)-2)), domain, message, display))
            if self.upload:
                file = "vizscan.kenz"
                self.uploader(self.content[i], file)
        return

    # runs all enumeration modules
    def enumall(self):
        self.subenum()
        self.dnsenum()
        self.asnenum()
        self.portenum()
        self.servenum()
        self.webenum()
        self.headenum()
        self.socenum()
        self.keysenum()
        self.conenum()
        self.repoenum()
        # experimental ones
        # self.repenum()
        # self.urlenum()
        # self.urlheadenum()
        return

    # runs all scanning modules
    def scanall(self):
        self.wafscan()
        self.shodscan()
        self.favscan()
        self.idscan("workflow")
        self.subscan()
        self.buckscan()
        self.cvescan("workflow")
        self.vulnscan("workflow")
        self.bakscan()
        self.reposcan()
        self.vizscan()
        self.xssscan()
        self.portscan()
        # experimental ones
        # self.appscan()
        # self.urlscan()
        return

    # define your custom workflow - used while monitor's autohunt
    def hunt(self):
        self.subenum()
        self.dnsenum()
        self.asnenum()
        self.portenum()
        self.servenum()
        self.webenum()
        self.wafscan()
        self.sync()
        if self.distribute(["sync,urlenum-active,keysenum,socenum,sync,cvescan-workflow,sync monitor"]):
            pass
        else:
            self.urlenum('active')
            self.keysenum()
            self.socenum()
            self.cvescan("workflow")
        self.headenum()
        self.favscan()
        self.subscan()
        self.shodscan()
        self.buckscan()
        self.vulnscan("workflow")
        self.vizscan()
        self.sync(True)
        self.freaker("keyleaks", "monitor")
        self.freaker("basic-xss-fuzz", "monitor")
        self.sync()
        # experimental ones
        # self.bakscan()
        # self.xssscan()
        # self.freaker("wapiti-scan", "monitor")
        # self.freaker("zap-scan", "monitor")
        # self.repoenum()
        # self.conenum()
        # self.repenum()
        # self.portscan()
        # self.reposcan()
        # self.urlheadenum()
        # self.appscan()
        # self.urlscan()
        return

    # runs all modules
    def recon(self):
        self.enumall()
        self.scanall()
        return
    
    # runs freaker module
    def freaker(self, exploit, target=""):
        trg = ""
        if len(target)>0:
            trg = "-t "+target
            self.sendMessage("[freaker][{1}] {0}".format(target, exploit))
        else:
            self.sendMessage("[freaker][{1}] *".format(target, exploit))
        os.system("freaker -c {0} -r {1} {2}".format("configs/freaker.yaml", exploit, trg))
        return

    # synchronizes the local kenzerdb with github
    def sync(self, pull=False):
        os.system("rm {0}../.git/index.lock".format(_kenzerdb))
        if not pull:
            for tar in os.listdir(_kenzerdb):
                    self.mergesplit(tar.lower())
            os.system("find {0} -maxdepth 1 -type f -delete".format(_kenzerdb))
            if _logging == "False":
                    self.remlog()
            for tar in os.listdir(_kenzerdb):
                if _splitting == "True":
                    self.splitkenz(tar.lower())
            os.system("cd {0}/../ && git remote set-url origin https://{1}@github.com/{2}/{3}.git && git pull && git add . && git commit -m \"data-{4}`date`)\" && git push".format(
                _kenzerdb, _github, _user, _repo, _BotMail+"("))
            os.system("cd {0} && git pull && cd ../scripts && bash generate.sh && cd .. && git add . && git commit -m \"stats-{4}`date`)\" && git push".format(
                _kenzerdb, _github, _user, _repo, _BotMail+"("))
            for tar in os.listdir(_kenzerdb):
                    self.mergekenz(tar.lower())
        else:
            os.system("cd {0} && git remote set-url origin https://{1}@github.com/{2}/{3}.git && git pull".format(_kenzerdb, _github, _user, _repo, _BotMail+"("))
        self.sendMessage("[synced]")
        return

    # upgrades kenzer to latest version
    def upgrade(self):
        os.system("bash update.sh")
        self.sendMessage("[upgraded]")
        return

    # assembles delegates
    def assemble_delegates(self):
        global _delegates
        _delegates = []
        self.sendMessage("@**kenzer-delegates** assemble")
        return

    # assign delegates
    def assign_delegates(self, comnd):
        global _delegates
        for i in range(0, len(comnd)):
            self.sendMessage("@**{0}** {1}".format(_delegates[i], comnd[i]))

    # distribute commands to delegates    
    def distribute(self, comnd):
        global _delegates
        _delegates = list(set(_delegates))
        if(len(comnd)>len(_delegates)):
            self.sendMessage("[exception] require {0} more delegates. continuing...".format(len(comnd)-len(_delegates)))
            return False
        self.assign_delegates(comnd)
        return True

    # disseminate files to delegates    
    def disseminate(self, command):
        global _delegates
        all_commands = {
            "portenum": ["subenum", "asnenum", "dnsenum"],
            "conenum": ["webenum"],
            "subscan": ["subenum", "webenum"],
            "cvescan": ["webenum", "wafscan"],
            "vulnscan": ["webenum", "wafscan"],
            "cscan": ["webenum", "wafscan"],
            "buckscan": ["subenum"],
            "favscan": ["webenum"],
            "idscan": ["webenum", "wafscan"],
            "appscan": ["webenum", "urlenum", "wafscan"],
            "xssscan": ["webenum", "urlenum", "wafscan"],
            "urlscan": ["urlenum"]
        }
        _delegates = list(set(_delegates))
        if len(command.split(" "))>2:
            self.sendMessage("[exception] ony one target allowed.")
            return False
        comnd = command.split(" ")[0].split(",")[0].split("-")[0]
        if comnd not in list(all_commands.keys()):
            self.sendMessage("[exception] command not allowed.")
            return False
        fomnda = all_commands[comnd]
        targ = command.split(" ")[1]
        if validators.domain(targ) == True:
                targ = targ
        else:
            try:
                ipaddress.ip_network(targ)
                targ = targ.replace("/", "#")
            except ValueError:
                self.sendMessage("[invalid] {0}".format(targ))
                return False
        if comnd not in list(all_commands.keys()):
            self.sendMessage("[exception] command not allowed.")
            return False
        for fomnd in fomnda:
            os.system("cd {0} && split -n l/{1} {2} {2}.split. -d -a 1".format(_kenzerdb+targ, len(_delegates), fomnd+".kenz"))
            for i in range(0,len(_delegates)):
                os.system("mv {0}{1}.{2} {0}{1}.{3}".format(_kenzerdb+targ+"/", fomnd+".kenz.split", i, _delegates[i]))
        self.sync()
        self.assign_delegates(["sync-pull"]*len(_delegates))
        time.sleep(60)
        self.assign_delegates([command]*len(_delegates))
        return True
    
    # controls
    def process(self, text):
        global _delegates, _waf
        self.content = text["content"].split()
        self.sender_email = text["sender_email"]
        self.type = text["type"]
        self.display_recipient = text['display_recipient']
        self.subject = text['subject']
        content = self.content
        print(content)
        if self.sender_email == _BotMail:
            return
        try:
            if len(content) > 1 and content[0].lower() == "@**{0}**".format(_BotMail.split('@')[0].replace("-bot", "")):
                for comd in content[1].split(","):
                    if comd.lower() == "man":
                        if len(content) == 2:
                            self.man()
                        else:
                            message = "excuse me???"
                            self.sendMessage(message)
                    elif comd.lower() == "monitor":
                        if content[2].lower() == "normalize":
                            self.normalize()
                        elif content[2].lower() == "db":
                            self.monitor_kenzerdb()
                        elif content[2].lower() == "autohunt":
                            if len(content) == 4:
                                self.monitor_autohunt(int(content[3]))
                            else:
                                self.monitor_autohunt()
                        else:
                            self.monitor()
                    elif comd.lower() == "blacklist":
                        self.blacklist()
                    elif comd.lower() == "whitelist":
                        self.whitelist()
                    elif comd.lower() == "program":
                        self.program()
                    elif comd.split("-")[0].lower() == "subenum":
                        if len(comd.split("-")) > 1:
                            self.subenum(comd.split("-")[1].lower())
                        else:
                            self.subenum()
                    elif comd.lower() == "repenum":
                        self.repenum()
                    elif comd.lower() == "repoenum":
                        self.repoenum()
                    elif comd.lower() == "webenum":
                        self.webenum()
                    elif comd.lower() == "servenum":
                        self.servenum()
                    elif comd.lower() == "socenum":
                        self.socenum()
                    elif comd.lower() == "keysenum":
                        self.keysenum()
                    elif comd.lower() == "headenum":
                        self.headenum()
                    elif comd.lower() == "wafscan":
                        self.wafscan()
                    elif comd.lower() == "urlheadenum":
                        self.urlheadenum()
                    elif comd.lower() == "asnenum":
                        self.asnenum()
                    elif comd.lower() == "dnsenum":
                        self.dnsenum()
                    elif comd.lower() == "conenum":
                        self.conenum()
                    elif comd.lower() == "favscan":
                        self.favscan()
                    elif comd.lower() == "xssscan":
                        self.xssscan()
                    elif comd.lower() == "appscan":
                        self.appscan()
                    elif comd.split("-")[0].lower() == "portenum":
                        if len(comd.split("-")) > 1:
                            self.portenum(comd.split("-")[1].lower())
                        else:
                            self.portenum()
                    elif comd.split("-")[0].lower() == "urlenum":
                        if len(comd.split("-")) > 1:
                            self.urlenum(comd.split("-")[1].lower())
                        else:
                            self.urlenum()
                    elif comd.lower() == "subscan":
                        self.subscan()
                    elif comd.split("-")[0].lower() == "cscan":
                        if len(comd.split("-")) > 1:
                            for sev in range(1,len(comd.split("-"))):
                                self.cscan(comd.split("-")[sev].lower())
                        else:
                            self.cscan()
                    elif comd.split("-")[0].lower() == "urlscan":
                        if len(comd.split("-")) > 1:
                            for sev in range(1,len(comd.split("-"))):
                                self.urlscan(comd.split("-")[sev].lower())
                        else:
                            self.urlscan()
                    elif comd.split("-")[0].lower() == "cvescan":
                        if len(comd.split("-")) > 1:
                            for sev in range(1,len(comd.split("-"))):
                                self.cvescan(comd.split("-")[sev].lower())
                        else:
                            self.cvescan()
                    elif comd.split("-")[0].lower() == "vulnscan":
                        if len(comd.split("-")) > 1:
                            for sev in range(1,len(comd.split("-"))):
                                self.vulnscan(comd.split("-")[sev].lower())
                        else:
                            self.vulnscan()
                    elif comd.lower() == "portscan":
                        self.portscan()
                    elif comd.lower() == "bakscan":
                        self.bakscan()
                    elif comd.lower() == "shodscan":
                        self.shodscan()
                    elif comd.lower() == "reposcan":
                        self.reposcan()
                    elif comd.split("-")[0].lower() == "idscan":
                        if len(comd.split("-")) > 1:
                            for sev in range(1,len(comd.split("-"))):
                                self.idscan(comd.split("-")[sev].lower())
                        else:
                            self.idscan()
                    elif comd.split("-")[0].lower() == "vizscan":
                        if len(comd.split("-")) > 1:
                            self.vizscan(comd.split("-")[1].lower())
                        else:
                            self.vizscan()
                    elif comd.lower() == "buckscan":
                        self.buckscan()
                    elif comd.lower() == "disseminate":
                        if self.disseminate(" ".join(content[2:]).lower()):
                            self.sendMessage("[disseminated]")
                    elif comd.lower() == "enum":
                        self.enumall()
                    elif comd.lower() == "scan":
                        self.scanall()
                    elif comd.lower() == "hunt":
                        self.hunt()
                    elif comd.lower() == "recon":
                        self.recon()
                    elif comd.split("-")[0].lower() == "sync":
                        if len(comd.split("-")) > 1:
                            if comd.split("-")[1]=="pull":
                                self.sync(pull=True)
                        else:
                            self.sync()    
                    elif comd.lower() == "freaker":
                        if len(content) >= 4:
                            for i in range(3, len(content)):
                                self.freaker(content[2], content[i].lower())
                                self.sendMessage("[freaker][finished] {0}".format(content[i].lower()))
                        else:
                            self.freaker(content[2])
                    elif comd.lower() == "upgrade":
                        self.upgrade()
                    elif comd.lower() == "upload":
                        self.upload = not self.upload
                        self.sendMessage("upload: "+str(self.upload))
                    elif comd.lower() == "waf":
                        if _waf == "True":
                            _waf = "False"
                        else:
                            _waf = "True"
                        self.sendMessage("avoid-waf: "+_waf)
                    elif comd.lower() == "proxy":
                        if ("http" not in _proxyurl and "socks" not in _proxyurl) or _eproxy
                            os.environ["http_proxy"] = ""
                            os.environ["https_proxy"] = ""
                            _eproxy = False
                        else:
                            os.environ["http_proxy"] = _proxyurl
                            os.environ["https_proxy"] = _proxyurl
                            _eproxy = True
                        self.sendMessage("enabled-proxy: "+str(_eproxy))
                    else:
                        message = self.chatbot.get_response(' '.join(self.content))
                        message = message.serialize()['text']
                        self.sendMessage(message)
            if len(content) > 1 and content[0].lower() == "@**kenzer-delegates**":
                if content[1].lower() == "assemble":
                    self.sendMessage("@**kenzer-delegates** reporting")
                elif content[1].lower() == "reporting":
                    _delegates.append(self.sender_email.split('@')[0].replace("-bot",""))
                    
        except Exception as exception:
            self.sendMessage("[exception] {0}:{1}".format(
                type(exception).__name__, str(exception)))
            print(exception.__class__.__name__ + ": " + str(exception))
        return

# main


def main():
    bot = Kenzer()
    bot.client.call_on_each_message(bot.process)


# runs main
if __name__ == "__main__":
    main()
