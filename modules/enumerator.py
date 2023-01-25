# imports
import os

# enumerator


class Enumerator:

    # initializations
    def __init__(self, domain, db, kenzer, botn, dtype):
        self.domain = domain
        self.organization = domain
        self.dtype = dtype
        self.botn = botn
        if dtype:
            self.path = db+self.organization
        else:
            self.path = db+self.organization.replace("/", "#")
        self.resources = kenzer+"resources"
        self.templates = self.resources+"/kenzer-templates/"
        if(os.path.exists(self.path) == False):
            os.system("mkdir "+self.path)

    # core enumerator modules

    # initializes the program to which target belongs
    def program(self, program=""):
        domain = self.domain
        path = self.path
        output = path+"/program.kenz"
        programs = []
        if(len(program) > 0):
            programs.append(program)
            if(os.path.exists(output)):
                with open(output, "r") as f:
                    programs.extend(f.read().splitlines())
                    programs = list(set(programs))
                    programs.sort()
                    f.close()
            with open(output, "w") as f:
                f.writelines("%s\n" % line for line in programs)
                f.close()
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # initializes & removes blacklisted targets
    def blacklist(self, blacklist=""):
        domain = self.domain
        path = self.path
        output = path+"/blacklist.kenz"
        botn = self.botn
        files = []
        for x in os.listdir(path):
            if (x.endswith(".mon") or x.endswith(".kenz") or x.endswith(".log") or x.endswith(".old") or x.endswith(botn)) and (x not in ["blacklist.kenz", "whitelist.kenz", "program.kenz", "repoenum.kenz", "reposcan.kenz", "portscan.kenz", "appscan.kenz"]):
                files.append(x)
        blacklists = []
        if(len(blacklist) > 0):
            blacklists.append(blacklist)
            if(os.path.exists(output)):
                with open(output, "r") as f:
                    blacklists.extend(f.read().splitlines())
                    blacklists = list(set(blacklists))
                    blacklists.sort()
                    f.close()
            with open(output, "w") as f:
                f.writelines("%s\n" % line for line in blacklists)
                f.close()
        line = 0
        if(os.path.exists(output)):
            with open(output, "r") as f:
                blacklists = f.read().splitlines()
            for key in blacklists:
                for file in files:
                    if(os.path.exists(path+"/"+file)):
                        os.system(
                            "ex +g/\"{0}\"/d -cwq {1}*".format(key.strip(), path+"/"+file))
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # initializes & keeps only whitelisted targets
    def whitelist(self, whitelist=""):
        domain = self.domain
        path = self.path
        output = path+"/whitelist.kenz"
        botn = self.botn
        files = []
        for x in os.listdir(path):
            if (x.endswith(".mon") or x.endswith(".kenz") or x.endswith(".log") or x.endswith(".old") or x.endswith(botn)) and (x not in ["blacklist.kenz", "whitelist.kenz", "program.kenz", "repoenum.kenz", "reposcan.kenz", "portscan.kenz", "appscan.kenz"]):
                files.append(x)
        whitelists = []
        if(len(whitelist) > 0):
            whitelists.append(whitelist)
            if(os.path.exists(output)):
                with open(output, "r") as f:
                    whitelists.extend(f.read().splitlines())
                    whitelists = list(set(whitelists))
                    whitelists.sort()
                    f.close()
            with open(output, "w") as f:
                f.writelines("%s\n" % line for line in whitelists)
                f.close()
        line = 0
        if(os.path.exists(output)):
            with open(output, "r") as f:
                whitelists = f.read().splitlines()
            for key in whitelists:
                for file in files:
                    if(os.path.exists(path+"/"+file)):
                        os.system(
                            "ex +v/\"{0}\"/d -cwq {1}*".format(key.strip(), path+"/"+file))
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates subdomains
    def subenum(self, github, shodan, viewdns, whoisxml, mode=""):
        domain = self.domain
        path = self.path
        output = path+"/subenum.kenz"  
        dtype = self.dtype
        if(os.path.exists(output)):
            os.system("mv {0} {0}.old".format(output))  
        if dtype:
            if(mode == "active"):
                self.shuffledns()
                self.dnsgen()
            elif(mode == "passive"):
                self.subfinder()
                self.amass()
                self.netlas()
                self.gitsub(github)
            elif(mode == "fast"):
                self.subfinder()
                self.netlas()
            else:
                self.subfinder()
                self.amass()
                self.netlas()
                self.gitsub(github)
                self.shuffledns()
                self.dnsgen()
            self.blacklist()
            self.whitelist()
            if domain != "monitor":
                os.system("cat {0}/amass.log {0}/subfinder.log {0}/subenum.kenz.old {0}/shuffledns.log {0}/dnsgen.log {0}/gitsub.log | grep \"{2}\" | sort -u > {1}".format(path, output, domain))
            else:
                os.system("cat {0}/netlas.log {0}/amass.log {0}/subfinder.log {0}/subenum.kenz.old {0}/shuffledns.log {0}/dnsgen.log {0}/gitsub.log | sort -u > {1}".format(path, output, domain))
        else:
            if(mode == "active"):
                self.tlsx()
                self.revdns()
            elif(mode=="passive" or mode=="fast"):
                self.rNXScan(whoisxml=whoisxml, shodan=shodan, viewdns=viewdns)
                self.mapcidr()
                self.netlas()
            else:
                self.rNXScan(whoisxml=whoisxml, shodan=shodan, viewdns=viewdns)
                self.tlsx()
                self.revdns()
                self.mapcidr()
                self.netlas()
            self.blacklist()
            self.whitelist()
            os.system("cat {0}/mapcidr.log {0}/netlas.log {0}/revdns.log {0}/revNXScan.log {0}/tlsx.log {0}/subenum.kenz.old  | sort -u > {1}".format(path, output, domain))
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates webservers
    def webenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/portenum.kenz"
        if(os.path.exists(subs) == False):
            return("!portenum")
        output = path+"/httpx.log"
        dtype = self.dtype
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        self.httpx(subs, output)
        self.blacklist()
        self.whitelist()
        output = path+"/webenum.kenz"
        if(os.path.exists(output)):
            os.system("mv {0} {0}.old".format(output))
        os.system("cat {0}/servenum.kenz | egrep '\[http(s)*\]' | sed 's/] /:\/\//' | sed 's/\[//' > {0}/servenum.log".format(path))
        if domain != "monitor" and dtype:
            os.system("cat {0}/httpx.log {0}/webenum.kenz.old {0}/servenum.log | cut -d' ' -f 1 | grep \"{2}\" | sed 's/:\\(80\\|443\\)$//' > {1}".format(path, output, domain))
        else:
            os.system("cat {0}/httpx.log {0}/webenum.kenz.old {0}/servenum.log | cut -d' ' -f 1 | sed 's/:\\(80\\|443\\)$//' > {1}".format(path, output, domain))
        os.system("mv {0} {0}.tmp && cat {0}.tmp | sort -u > {0}".format(output))
        os.system("rm {0}.tmp".format(output))
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates additional information for webservers
    def headenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/webenum.kenz"
        if(os.path.exists(subs) == False):
            return("!webenum")
        output = path+"/headenum.kenz"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        extras = " -status-code -title -web-server -websocket -vhost -content-type -cdn -tech-detect -method -hash md5"
        self.httpx(subs, output, extras)
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates social media accounts
    def socenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/webenum.kenz"
        if(os.path.exists(subs) == False):
            return("!webenum")
        output = path+"/rescro.log"
        os.system("rescro -l {0} -s {1} -T 60 -t 8 -o {2}".format(subs,
                                                             self.templates+"/rescro/socials.yaml", output))
        out = path+"/socenum.kenz"
        if(os.path.exists(out)):
            os.system("mv {0} {0}.old".format(out))
        os.system("cat {0}/rescro.log | sort -u  > {1}".format(path, out))
        line = 0
        if(os.path.exists(out)):
            with open(out, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates sensitive api keys
    def keysenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/webenum.kenz"
        urls = path+"/urlenum.kenz"
        kinps = path+"/ikeysenum.log"
        if(os.path.exists(subs) == False):
            return("!webenum")
        output = path+"/rescro.log"
        os.system("cat {0} > {1}".format(subs, kinps))
        os.system("cat {0} | grep '\.js$' >> {1}".format(urls, kinps))
        os.system("rescro -l {0} -s {1} -T 60 -t 8 -o {2}".format(kinps,
                                                             self.templates+"/rescro/sensitives.yaml", output))
        out = path+"/keysenum.kenz"
        if(os.path.exists(out)):
            os.system("mv {0} {0}.old".format(out))
        os.system("cat {0}/rescro.log | sort -u  > {1}".format(path, out))
        line = 0
        if(os.path.exists(out)):
            with open(out, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates additional information for urls
    def urlheadenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/urlenum.kenz"
        if(os.path.exists(subs) == False):
            return("!urlenum")
        output = path+"/urlheadenum.kenz"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        extras = " -status-code -title -web-server -websocket -vhost -content-type -cdn -tech-detect -method -hash md5"
        self.httpx(subs, output, extras)
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates urls
    def urlenum(self, github, mode=""):
        if(mode == "active"):
            self.gospider()
            self.katana()
        elif(mode == "passive"):
            self.gau()
            self.urlhunter()
            self.waymore()
            self.giturl(github)
        else:
            self.gau()
            self.urlhunter()
            self.waymore()
            self.giturl(github)
            self.gospider()
            self.katana()
        self.blacklist()
        self.whitelist()    
        domain = self.domain
        path = self.path
        output = path+"/urlenum.kenz"
        if(os.path.exists(output)):
            os.system("mv {0} {0}.old".format(output))
        if domain!="monitor":
            os.system("cat {0}/urlenum.kenz.old {0}/gau.log {0}/urlhunter.log {0}/waymore.log {0}/giturl.log {0}/gospider.log {0}/katana.log | grep \"{2}\" | sort -u | urldedupe > {1}".format(path, output, domain))
        else:
            os.system("cat {0}/urlenum.kenz.old {0}/gau.log {0}/urlhunter.log {0}/waymore.log {0}/giturl.log {0}/gospider.log {0}/katana.log | sort -u | urldedupe > {1}".format(path, output))
        if domain!="monitor":
            os.system("cat {0}/conenum.kenz | grep -Eo '([-+.[:alnum:]]+://)?([-[:alnum:]]+.)*{2}(:[[:digit:]]+)?(/[[:graph:]]*)?' | httpx -sc -silent | grep \"200\" | cut -d \" \" -f 1 >> {1}".format(path, output, domain))
        else:
            os.system("cat {0}/conenum.kenz | grep -Eo '([-+.[:alnum:]]+://)?([-[:alnum:]]+.)*(:[[:digit:]]+)?(/[[:graph:]]*)?' | httpx -sc -silent | grep \"200\" | cut -d \" \" -f 1 >> {1}".format(path, output))
        cnt = 0
        while True:
            iline = 0
            if(os.path.exists(output)): 
                with open(output, encoding="ISO-8859-1") as f:
                    iline = len(f.readlines())
            oline = 0
            self.yourx()
            if(os.path.exists(path+"/yourx.log")): 
                with open(path+"/yourx.log", encoding="ISO-8859-1") as f:
                    oline = len(f.readlines())
            os.system("cat {0}/yourx.log | cut -d ' ' -f 2 > {1}".format(path,output))
            if(iline==oline) or (cnt==7):
                break
            cnt = cnt + 1
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates github repositories using RepoHunt
    def repoenum(self, github):
        domain = self.domain
        path = self.path
        output = path+"/repoenum.kenz"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system("RepoHunt -o {1} -v -k {2} -t {0}".format(github, output, domain))
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates reputation of a domain using DomREP
    def repenum(self, greynoise):
        domain = self.domain
        path = self.path
        subs = path+"/subenum.kenz"
        dtype = self.dtype
        output = path+"/repenum.kenz"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        if dtype:
            if(os.path.exists(subs) == False):
                return("!subenum")
            self.shuffsolv(subs, domain)
            subs = path+"/shuffsolv.log"
            os.system(
                "sudo domrep -l {0} -o {1} -g {2} -T 30".format(subs, output, greynoise))
        else:
            return 0
        self.blacklist()
        self.whitelist()
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates open ports using NXScan
    def portenum(self, mode="100"):
        if mode in ["100", "1000", "full"]:
            param = " --only-enumerate --ports "+mode
        elif mode in ["fast"]:
            param = " --only-shodan-enum "
        else:
            param = " --only-enumerate --ports 100"
        domain = self.domain
        path = self.path
        subs = path+"/subenum.kenz"
        asns = path+"/asnenum.kenz"
        dnss = path+"/dnsenum.kenz"
        dtype = self.dtype
        botn = self.botn
        output = path+"/portenum.kenz"
        if(os.path.exists(subs+".split."+botn) or os.path.exists(asns+".split."+botn) or os.path.exists(dnss+".split."+botn)):
            subs = subs+".split."+botn
            asns = asns+".split."+botn
            dnss = dnss+".split."+botn
            output = output+".split."+botn
        if (os.path.exists(output)):
            os.system("mv {0} {0}.old".format(output))
        if(os.path.exists(subs) == False):
            return("!subenum")
        if domain != "monitor" and dtype:
            self.shuffsolv(subs, domain)
            subs = path+"/shuffsolv.log"
        aslv = path+"/asnsolv.log"
        dslv = path+"/dnssolv.log"
        rslv = path+"/resolved.log"
        os.system(
            "cat {0} | cut -d ' ' -f 1 | sort -u > {1}".format(asns, aslv))
        os.system(
            "cat {0} | cut -d ' ' -f 2 | sort -u > {1}".format(dnss, dslv))
        os.system("cat {0} {1} {2} | sort -u > {3}".format(aslv, subs, dslv, rslv))
        os.system(
            "sudo NXScan {2} -l {0} -o {1}".format(rslv, path+"/nxscan", param))
        os.system(
            "cat {0}/nxscan/enum.txt {1}.old | sort -u > {1}".format(path, output))
        self.blacklist()
        self.whitelist()
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates services on open ports using NXScan
    def servenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/portenum.kenz"
        if(os.path.exists(subs) == False):
            return("!portenum")
        output = path+"/servenum.kenz"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system(
            "sudo NXScan --only-finger -l {0} -o {1}".format(subs, path+"/nxscan"))
        os.system(
            "cat {0}/nxscan/finger.txt | sort -u > {1}".format(path, output))
        self.blacklist()
        self.whitelist()
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates dns records using DNSX
    def dnsenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/subenum.kenz"
        if(os.path.exists(subs) == False):
            return("!subenum")
        output = path+"/dnsenum.kenz"
        if(os.path.exists(output)):
            os.system("mv {0} {0}.old".format(output))
        os.system("dnsx -l {0} -a -resp -retry 3 -silent | ts [A] >> {1}".format(subs, output))
        os.system("dnsx -l {0} -aaaa -resp -retry 3 -silent | ts [AAAA] >> {1}".format(subs, output))
        os.system("dnsx -l {0} -cname -resp -retry 3 -silent | ts [CNAME] >> {1}".format(subs, output))
        os.system("dnsx -l {0} -mx -resp -retry 3 -silent | ts [MX] >> {1}".format(subs, output))
        os.system("dnsx -l {0} -ptr -resp -retry 3 -silent | ts [PTR] >> {1}".format(subs, output))
        os.system("dnsx -l {0} -soa -resp -retry 3 -silent | ts [SOA] >> {1}".format(subs, output))
        os.system("dnsx -l {0} -txt -resp -retry 3 -silent | ts [TXT] >> {1}".format(subs, output))
        os.system("mv {0} {0}.tmp && cat {0}.tmp | sort -u > {0}".format(output))
        os.system("rm {0}.tmp".format(output))
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates asn using domlock
    def asnenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/subenum.kenz"
        if(os.path.exists(subs) == False):
            return("!subenum")
        output = path+"/asnenum.kenz"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system("domlock -l {0} -o {1} -T 30".format(subs, output))
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates files & directories
    def conenum(self):
        domain = self.domain
        path = self.path
        botn = self.botn
        output = path+"/conenum.kenz"
        subs = path+"/webenum.kenz"
        if(os.path.exists(subs+".split."+botn)):
            subs = subs+".split."+botn
            output = output+".split."+botn
        if(os.path.exists(subs) == False):
            return("!webenum")
        self.kiterunner(subs)
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system(
            "cat {0}/kiterunner.log | grep '] http' | sort -u > {1} ".format(path, output))
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # helper modules

    # downloads fresh list of public resolvers
    def getresolvers(self):
        output = self.resources+"/resolvers.txt"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system(
            "dnsvalidator -tL https://raw.githubusercontent.com/proabiral/Fresh-Resolvers/master/resolvers.txt -threads 250 -o {0}".format(output))

    def generateSubdomainsWordist(self):
        os.system("cd {0} && wget -q https://raw.githubusercontent.com/internetwache/CT_subdomains/master/top-100000.txt -O top-100000.txt".format(self.resources))
        os.system("cd {0} && wget -q https://raw.githubusercontent.com/cqsd/daily-commonspeak2/master/wordlists/subdomains.txt -O subsB.txt".format(self.resources))
        os.system("cd {0} && wget -q https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt -O subsC.txt".format(self.resources))
        output = self.resources+"/subsA.txt"
        os.system(
            "cat {0}/top-100000.txt | cut -d ',' -f 2 | sort -u > {1}".format(self.resources, output))
        output = self.resources+"/subdomains.txt"
        os.system(
            "cat {0}/subsA.txt {0}/subsB.txt {0}/subsC.txt | sort -u > {1}".format(self.resources, output))

    # resolves & removes wildcard subdomains using shuffledns, puredns & dnsx
    def shuffsolv(self, domains, domain):
        self.getresolvers()
        path = self.path + "/shuffsolv.log"
        if(os.path.exists(path)):
            os.system("rm {0}".format(path))
        os.system("shuffledns -strict-wildcard -r {3}/resolvers.txt -o {0} -v -list {1} -d {2}".format(
            path, domains, domain, self.resources))
        oldp = path
        path = self.path+"/puredns.log"
        os.system("puredns resolve {1} -r {2}/resolvers.txt -l 100 -t 25 -n 5 --rate-limit-trusted 50 -w {0} --wildcard-tests 50 ".format(
            path, oldp, self.resources))
        os.system("rm "+oldp)
        oldp = path
        path = self.path+"/shuffsolv.log"
        os.system(
            "cat {1} | dnsx -wd {2} -t 40 -retry 4 -silent -rl 50| sort -u > {0}".format(path, oldp, domain))
        os.system("rm "+oldp)
        return

    # enumerates subdomains using subfinder
    #"retains wildcard domains"
    def subfinder(self):
        domain = self.domain
        path = self.path
        output = path+"/subfinder.log"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system(
            "subfinder -all -t 30 -max-time 60 -o {0} -v -timeout 20 -d {1}".format(output, domain))
        return

    # enumerates subdomains using netlas
    def netlas(self):
        domain = self.domain
        path = self.path
        dtype = self.dtype
        output = path+"/netlas.log"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        if dtype:
            os.system("netlas download \"domain:*.{1}\" -d domain -c 100000 | jq '.data.domain' -r > {0}".format(output, domain))
        else:
            os.system("netlas download 'a:\"{1}\"' -d domain -c 100000 | jq '.data.domain' -r > {0}".format(output, domain))
        return

    # enumerates subdomains using amass
    def amass(self):
        domain = self.domain
        path = self.path
        output = path+"/amass.log"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system(
            "amass enum -config ~/.config/amass-config.ini -o {0} -d {1} -norecursive -noalts -nolocaldb".format(output, domain))
        return

    # bruteforce non-wildcard subdomains using shuffledns
    def shuffledns(self):
        self.getresolvers()
        self.generateSubdomainsWordist()
        domain = self.domain
        path = self.path
        output = path+"/shuffledns.log"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system("shuffledns -retries 5 -strict-wildcard -wt 30 -r {2}/resolvers.txt -w {2}/subdomains.txt -o {0} -v -d {1}".format(
            output, domain, self.resources))
        self.shuffsolv(output, domain)
        os.system("rm {0} && mv {1} {0}".format(output, path+"/shuffsolv.log"))
        return

    # enumerates subdomains using dnsgen
    def dnsgen(self):
        domain = self.domain
        path = self.path
        output = path+"/dnsgen.log"
        os.system(
            "cat {0}/amass.log {0}/subfinder.log {0}/subenum.kenz.old {0}/shuffledns.log | sort -u | dnsgen - > {1}".format(path, output))
        self.shuffsolv(output, domain)
        os.system("rm {0} && mv {1} {0}".format(output, path+"/shuffsolv.log"))
        return
        
    # probes for web servers using httpx
    def httpx(self, domains, output, extras=""):
        os.system(
            "httpx {2}  -no-color -l {0} -rl 70 -threads 70 -retries 2 -timeout 8 -verbose -o {1} -proxy \\\"$GOPROXY\\\" ".format(domains, output, extras))
        return

    # enumerates files & directories using kiterunner
    def kiterunner(self, domains):
        domain = self.domain
        path = self.path
        path += "/kiterunner.log"
        if(os.path.exists(path)):
            os.system("rm {0}".format(path))
        os.system(
            "kr brute {0} -w {2}/kenzer-templates/kiterunner.lst -t 8s -j 80 -x 5 -q -o text | tee -a {1}".format(domains, path, self.resources))
        return

    # enumerates urls using gau
    def gau(self):
        domain = self.domain
        path = self.path
        path += "/gau.log"
        if(os.path.exists(path)):
            os.system("rm {0}".format(path))
        os.system("gau --threads 50 --subs --o {0} {1}".format(path, domain))
        return
 
    # enumerates subdomains using hakrevdns
    def revdns(self):
        domain = self.domain
        path = self.path
        output = path + "/hakrevdns.log"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system("mapcidr -silent -cidr {1} | hakrevdns -d -t 100 | dnsx -silent | sort -u > {0}".format(output, domain))
        output = path + "/revdns.log"
        os.system("cat {0}/../*/subenum.kenz | sort -u > {0}/subtemp.log".format(path))
        os.system("comm -23 {0}/hakrevdns.log {0}/subtemp.log | sort -u > {1}".format(path, output))
        os.system("rm {0}/subtemp.log".format(path))
        return

    # enumerates subdomains using NXScan
    def rNXScan(self, whoisxml="", shodan="", viewdns=""):
        domain = self.domain
        path = self.path
        output = path + "/rnxscan.log"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        params = ""
        if len(whoisxml)>0:
            params = params + "--whois-xml-api-key "+whoisxml
        if len(viewdns)>0:
            params = params + "--viewdns-api-key "+viewdns
        if len(shodan)>0:
            params = params + "--shodan-api-key "+shodan
        os.system("echo {0} > {1}/inxs && NXScan --only-hostnames -l {1}/inxs -o {1}/nxscan {2} && mv {1}/nxscan/hosts.txt {3} && rm {1}/inxs".format(domain, self.path, params, output))
        output = path + "/revNXScan.log"
        os.system("cat {0}/../*/subenum.kenz | sort -u > {0}/subtemp.log".format(path))
        os.system("comm -23 {0}/rnxscan.log {0}/subtemp.log | sort -u > {1}".format(path, output))
        os.system("rm {0}/subtemp.log".format(path))
        return

    # enumerates ip using mapcidr
    def mapcidr(self):
        domain = self.domain
        path = self.path
        output = path + "/mapcidr.log"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system("mapcidr -silent -cidr {1} | sort -u > {0}".format(output, domain))
        return

    # enumerates subdomains using tlsx
    def tlsx(self):
        domain = self.domain
        path = self.path
        output = path + "/tlsx.log"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system("echo {1} | tlsx -san -cn -silent -resp-only -sm auto | dnsx -silent | sort -u > {0}".format(output, domain))
        return

    # enumerates urls using gospider
    def gospider(self):
        domain = self.domain
        path = self.path
        path += "/gospider.log"
        if(os.path.exists(path)):
            os.system("rm {0}".format(path))
        os.system(
            "gospider -S {0}/webenum.kenz -w -r --sitemap -d 5 -c 50 -t 25 -o {0}/gocrawler -q -u web | cut -d \" \" -f 5|  sort -u | grep \"\\S\" > {1}".format(self.path, path))
        return
    
    # enumerates urls using katana
    def katana(self):
        domain = self.domain
        path = self.path
        path += "/katana.log"
        if(os.path.exists(path)):
            os.system("rm {0}".format(path))
        os.system("katana -list {0}/webenum.kenz -o {1} -jc -kf -sc -retry 2 -d 3 -aff -c 25 -p 15 -fs fqdn -proxy \\\"$GOPROXY\\\" ".format(self.path, path))
        return

    # clusters urls using YourX
    def yourx(self):
        domain = self.domain
        path = self.path
        path += "/yourx.log"
        if(os.path.exists(path)):
            os.system("rm {0}".format(path))
        os.system("YourX -l {0}/urlenum.kenz -t 100 -u -o {1}".format(self.path, path))
        return

    # enumerates urls using github-endpoints
    def giturl(self, github):
        domain = self.domain
        path = self.path
        path += "/giturl.log"
        api = github
        if(os.path.exists(path)):
            os.system("rm {0}".format(path))
        os.system(
            "github-endpoints -all -t {2} -d {1} -o {0}".format(path, domain, api))
        return

    # enumerates urls using urlhunter
    def urlhunter(self):
        domain = self.domain
        path = self.path
        path += "/urlhunter.log"
        inp = path+"/urlhunter"
        if(os.path.exists(path)):
            os.system("rm {0}".format(path))
        os.system("echo {1} > {2} && urlhunter -date latest -o {0} -keywords {2} && rm {2}".format(path, domain, inp))
        os.system("mv {0} {0}.tmp && cat {0}.tmp | grep '\(\W\|^\){1}' > {0}".format(path, domain))
        return

    # enumerates urls using waymore
    def waymore(self):
        domain = self.domain
        path = self.path
        path += "/waymore.log"
        if(os.path.exists(path)):
            os.system("rm {0}".format(path))
        os.system("waymore -i {0} -mode U -p 5 -r 3".format(domain))
        os.system("mv ~/results/{0}/waymore.txt {1}".format(domain, path))
        return

    # enumerates subdomains using github-endpoints
    def gitsub(self, github):
        domain = self.domain
        path = self.path
        path += "/gitsub.log"
        api = github
        if(os.path.exists(path)):
            os.system("mv {0} {0}.old".format(path))
        os.system(
            "github-subdomains -e -t {2} -d {1} -o {0}".format(path, domain, api))
        return

    # splits files greater than 90mb
    def splitkenz(self):
        domain = self.domain
        path = self.path
        files = []
        for x in os.listdir(path):
            if x.endswith(".kenz") and x not in ["blacklist.kenz", "whitelist.kenz", "portscan.kenz", "program.kenz", "appscan.kenz"]:
                files.append(x)
        for file in files:
            fil = path+"/"+file
            if os.stat(fil).st_size > 90000000:
                os.system("split -b 90M {0} {0}. -d".format(fil))
                os.system("rm {0}".format(fil))
        return

    # merges files if necessary
    def mergekenz(self):
        domain = self.domain
        path = self.path
        botn = self.botn
        for x in os.listdir(path):
            if (x.endswith(botn)) and (".split." in x):
                os.system("cat {1}/{0}.kenz.split.{2} | sort -u >> {1}/{0}.kenz".format(x.split(".")[0], path, botn))
                os.system("rm {0}/{1}.kenz.split.{2}".format(path, x.split(".")[0], botn))
                os.system("mv {1}/{0}.kenz {1}/{0}.kenz.tmp && cat {1}/{0}.kenz.tmp | sort -u > {1}/{0}.kenz && rm {1}/{0}.kenz.tmp".format(x.split(".")[0], path))
        return
    
    # merges files if necessary
    def mergesplit(self):
        domain = self.domain
        path = self.path
        botn = self.botn
        for x in os.listdir(path):
            if (x.endswith(botn)) and (".split." in x):
                if x.split(".")[0] not in ["appscan"]:
                    os.system("cat {1}/{0}.kenz.split.{2} | sort -u >> {1}/{0}.kenz".format(x.split(".")[0], path, botn))
                    os.system("rm {0}/{1}.kenz.split.{2}".format(path, x.split(".")[0], botn))
                    os.system("mv {1}/{0}.kenz {1}/{0}.kenz.tmp && cat {1}/{0}.kenz.tmp | sort -u > {1}/{0}.kenz && rm {1}/{0}.kenz.tmp".format(x.split(".")[0], path))
                else:
                    os.system("cat {1}/{0}.kenz.split.{2} >> {1}/{0}.kenz".format(x.split(".")[0], path, botn))
                    os.system("rm {0}/{1}.kenz.split.{2}".format(path, x.split(".")[0], botn))
                    os.system("mv {1}/{0}.kenz {1}/{0}.kenz.tmp && cat {1}/{0}.kenz.tmp > {1}/{0}.kenz && rm {1}/{0}.kenz.tmp".format(x.split(".")[0], path))
        return