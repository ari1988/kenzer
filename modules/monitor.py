# imports
import os
import tldextract
from datetime import datetime
import timeago
import json
import socket
import ipaddress

# monitor


class Monitor:

    # initializations
    def __init__(self, db, domains=""):
        self.domains = domains
        self.organization = "monitor"
        self.db = db
        self.path = db+self.organization
        if(os.path.exists(self.path) == False):
            os.system("mkdir "+self.path)

    # core monitor modules

    # enumerates subdomains using certex
    def certex(self):
        domains = self.domains
        path = self.path
        templ = path+"/certex.mon"
        if len(domains) == 0:
            os.system(
                'certex -l -f {0} -L 1 >> {1} &'.format(self.db+"../summary/targets.txt", templ))
        else:
            os.system('certex -l -t {0} -L 1 >> {1} &'.format(domains, templ))
        return

    # enumerates subdomains using subfinder & removes wildcards using dnsx
    def subfinder(self):
        path = self.path
        output = path+"/subfinder.mon"
        os.system(
            "for i in `cat {0}`; do subfinder -s chaos,crtsh,certspotter,dnsdumpster,c99,rapiddns,waybackarchive,dnsrepo -d $i | sort -u > {1}.out && for j in `cat {2}/$i/blacklist.kenz`; do ex +g/$j/d -cwq {1}.out; done && for j in `cat {2}/$i/whitelist.kenz`; do ex +v/$j/d -cwq {1}.out; done && cat {2}/$i/subenum.kenz | sort -u > {1}.inp && comm -32 {1}.out {1}.inp | sort -u | dnsx -wd $i >> {1} && rm {1}.* && sleep 1m; done &".format(self.db+"../summary/domain.txt", output, self.db))
        return

    # initializes timestamps using zstamp
    def timestamp(self):
        path = self.path
        inp = path+"/subenum.mon"
        out = path+"/zstamp.log"
        if(os.path.exists(out)):
            os.system("rm "+out)
        os.system("zstamp -l {0} -o {1}".format(inp, out))
        inp = out
        out = path+"/zstamp.mon"
        if(os.path.exists(out) == False):
            past = {}
        else:
            with open(out, 'r', encoding="ISO-8859-1") as f:
                past = json.load(f)
        with open(inp, 'r', encoding="ISO-8859-1") as f:
            current = json.load(f)
        ilist = []
        for dom in list(current.keys()):
            if dom not in list(past.keys()) or len(past)==0:
                past[dom] = current[dom]
                ilist.append(dom)
            else:
                ago = timeago.format(datetime.strptime(past[dom], "%Y-%m-%d %H:%M:%S.%f"), datetime.strptime(current[dom], "%Y-%m-%d %H:%M:%S.%f"))
                if ("day" in ago.split(" ")[1] and int(ago.split(" ")[0]) >= 6):
                    past[dom] = current[dom]
                    ilist.append(dom)
        with open(out, 'w') as f:
            json.dump(past, f, sort_keys=True, indent=2)
        out = path+"/subenum.mon"
        with open(out, 'w', encoding="ISO-8859-1") as f:
            f.writelines("%s\n" % line for line in ilist)

    # initialize automated hunt
    def initialize(self):
        path = self.path
        cer = path+"/certex.mon"
        sub = path+"/subfinder.mon"
        out = path+"/subenum.mon"
        ocer = path+"/certex.log"
        os.system("mv {0} {1}".format(cer, ocer))
        os.system('cat {0} | grep "\[+\]" | cut -d " " -f 2 | sed -r "s~\\x01?(\\x1B\\(B)?\\x1B\\[([0-9;]*)?[JKmsu]\\x02?~~g" >> {1}'.format(ocer, cer))
        os.system("cat {0} {1} | sort -u > {2} && rm {0} {1}".format(cer, sub, out))
        os.system("mv {0} {0}.log").format(out)
        os.system("cat {0}/../*/subenum.kenz | sort -u > {0}/subtemp.log".format(path))
        os.system("comm -23 {0}.log {1}/subtemp.log | sort -u > {0}".format(out, path))
        os.system("rm {0}/subtemp.log".format(path))
        self.timestamp()

    # reinitialize automated hunt
    def reinitialize(self):
        os.system(
            "rm -r {0}/../*.kenz {0}/*enum.kenz {0}/*scan.kenz {0}/*.log {0}/*.old {0}/nuclei {0}/jaeles {0}/passive-jaeles {0}/nxscan {0}/gocrawler".format(self.path))

    # enumerates & filters subdomains
    def subenum(self):
        kenzerdb = self.db
        subenum = self.path+"/subenum.mon"
        if(os.path.exists(subenum) == False):
            return
        with open(subenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for subdomain in domains:
            try:
                if len(subdomain)<=0:
                    continue
                extracted = tldextract.extract(subdomain)
                domain = "{0}.{1}".format(extracted.domain, extracted.suffix)
                subdo = "{0}.{1}.{2}".format(extracted.subdomain, extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    try:
                        ipd = socket.gethostbyname(subdo.lower().strip("."))
                    except:
                        continue
                    with open(kenzerdb+"../summary/cidr.txt", 'r', encoding="ISO-8859-1") as cf:
                        cidrs = cf.readlines()
                        for cidr in cidrs:
                            try:
                                if ipaddress.ip_address(ipd) in ipaddress.ip_network(cidr):
                                   destination = kenzerdb+cidr.replace("/","#")
                                   break
                            except:
                                continue
                if not os.path.exists(destination):
                    continue
                with open(destination+"/monitor.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(subdomain)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/monitor.kenz"))
                os.system("rm {0}.old".format(destination+"/monitor.kenz"))
                if(os.path.exists(destination+"/blacklist.kenz")):
                    with open(destination+"/blacklist.kenz", "r") as f:
                        blacklist = f.read().splitlines()
                    for key in blacklist:
                        os.system(
                            "ex +g/\"{0}\"/d -cwq {1}".format(key.strip(), destination+"/monitor.kenz"))
                if(os.path.exists(destination+"/whitelist.kenz")):
                    with open(destination+"/whitelist.kenz", "r") as f:
                        whitelist = f.read().splitlines()
                    for key in whitelist:
                        os.system(
                            "ex +v/\"{0}\"/d -cwq {1}".format(key.strip(), destination+"/monitor.kenz"))
            except:
                continue
        output = self.path+"/subenum.kenz"
        os.system(
            "cat {0}*/monitor.kenz | sort -u > {1}".format(kenzerdb, output))
        os.system("rm {0}*/monitor.kenz".format(kenzerdb))
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # normalizes enumerations
    def normalize(self):
        self.norm_subenum()
        self.norm_portenum()
        self.norm_webenum()
        self.norm_bakscan()
        self.norm_wafscan()
        self.norm_dnsenum()
        self.norm_servenum()
        self.norm_conenum()
        self.norm_repenum()
        self.norm_asnenum()
        self.norm_headenum()
        self.norm_shodscan()
        self.norm_favscan()
        self.norm_idscan()
        self.norm_cvescan()
        self.norm_subscan()
        self.norm_cscan()
        self.norm_vulnscan()
        self.norm_buckscan()
        self.norm_vizscan()
        self.norm_keysenum()
        self.norm_socenum()
        self.norm_urlenum()
        self.reinitialize()
        return

    # normalizes subenum
    def norm_subenum(self):
        kenzerdb = self.db
        subenum = self.path+"/subenum.kenz"
        if(os.path.exists(subenum) == False):
            return
        with open(subenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for subdomain in domains:
            try:
                if len(subdomain)<=0:
                    continue
                extracted = tldextract.extract(subdomain)
                domain = "{0}.{1}".format(extracted.domain, extracted.suffix)
                subdo = "{0}.{1}.{2}".format(extracted.subdomain, extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    try:
                        ipd = socket.gethostbyname(subdo.lower().strip("."))
                    except:
                        continue
                    with open(kenzerdb+"../summary/cidr.txt", 'r', encoding="ISO-8859-1") as cf:
                        cidrs = cf.readlines()
                        for cidr in cidrs:
                            try:
                                if ipaddress.ip_address(ipd) in ipaddress.ip_network(cidr):
                                   destination = kenzerdb+cidr.replace("/","#")
                                   break
                            except:
                                continue
                if not os.path.exists(destination):
                    continue
                with open(destination+"/subenum.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(subdomain)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/subenum.kenz"))
                os.system("rm {0}.old".format(destination+"/subenum.kenz"))
            except:
                continue
        return

    # normalizes portenum
    def norm_portenum(self):
        kenzerdb = self.db
        portenum = self.path+"/portenum.kenz"
        if(os.path.exists(portenum) == False):
            return
        with open(portenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for subdomain in domains:
            try:
                if len(subdomain)<=0:
                    continue
                extracted = tldextract.extract(subdomain)
                domain = "{0}.{1}".format(extracted.domain, extracted.suffix)
                subdo = "{0}.{1}.{2}".format(extracted.subdomain, extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    try:
                        ipd = socket.gethostbyname(subdo.lower().strip("."))
                    except:
                        continue
                    with open(kenzerdb+"../summary/cidr.txt", 'r', encoding="ISO-8859-1") as cf:
                        cidrs = cf.readlines()
                        for cidr in cidrs:
                            try:
                                if ipaddress.ip_address(ipd) in ipaddress.ip_network(cidr):
                                   destination = kenzerdb+cidr.replace("/","#")
                                   break
                            except:
                                continue
                if not os.path.exists(destination):
                    continue
                with open(destination+"/portenum.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(subdomain)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/portenum.kenz"))
                os.system("rm {0}.old".format(destination+"/portenum.kenz"))
            except:
                continue
        return

    # normalizes webenum
    def norm_webenum(self):
        kenzerdb = self.db
        webenum = self.path+"/webenum.kenz"
        if(os.path.exists(webenum) == False):
            return
        with open(webenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for subdomain in domains:
            try:
                if len(subdomain)<=0:
                    continue
                extracted = tldextract.extract(subdomain)
                domain = "{0}.{1}".format(extracted.domain, extracted.suffix)
                subdo = "{0}.{1}.{2}".format(extracted.subdomain, extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    try:
                        ipd = socket.gethostbyname(subdo.lower().strip("."))
                    except:
                        continue
                    with open(kenzerdb+"../summary/cidr.txt", 'r', encoding="ISO-8859-1") as cf:
                        cidrs = cf.readlines()
                        for cidr in cidrs:
                            try:
                                if ipaddress.ip_address(ipd) in ipaddress.ip_network(cidr):
                                   destination = kenzerdb+cidr.replace("/","#")
                                   break
                            except:
                                continue
                if not os.path.exists(destination):
                    continue
                with open(destination+"/webenum.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(subdomain)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/webenum.kenz"))
                os.system("rm {0}.old".format(destination+"/webenum.kenz"))
            except:
                continue
        return
    
    # normalizes bakscan
    def norm_bakscan(self):
        kenzerdb = self.db
        bakscan = self.path+"/bakscan.kenz"
        if(os.path.exists(bakscan) == False):
            return
        with open(bakscan, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for subdomain in domains:
            try:
                if len(subdomain)<=0:
                    continue
                extracted = tldextract.extract(subdomain)
                domain = "{0}.{1}".format(extracted.domain, extracted.suffix)
                subdo = "{0}.{1}.{2}".format(extracted.subdomain, extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    try:
                        ipd = socket.gethostbyname(subdo.lower().strip("."))
                    except:
                        continue
                    with open(kenzerdb+"../summary/cidr.txt", 'r', encoding="ISO-8859-1") as cf:
                        cidrs = cf.readlines()
                        for cidr in cidrs:
                            try:
                                if ipaddress.ip_address(ipd) in ipaddress.ip_network(cidr):
                                   destination = kenzerdb+cidr.replace("/","#")
                                   break
                            except:
                                continue
                if not os.path.exists(destination):
                    continue
                with open(destination+"/bakscan.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(subdomain)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/bakscan.kenz"))
                os.system("rm {0}.old".format(destination+"/bakscan.kenz"))
            except:
                continue
        return

    # normalizes urlenum
    def norm_urlenum(self):
        kenzerdb = self.db
        urlenum = self.path+"/urlenum.kenz"
        if(os.path.exists(urlenum) == False):
            return
        with open(urlenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for subdomain in domains:
            try:
                if len(subdomain)<=0:
                    continue
                extracted = tldextract.extract(subdomain)
                domain = "{0}.{1}".format(extracted.domain, extracted.suffix)
                subdo = "{0}.{1}.{2}".format(extracted.subdomain, extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    try:
                        ipd = socket.gethostbyname(subdo.lower().strip("."))
                    except:
                        continue
                    with open(kenzerdb+"../summary/cidr.txt", 'r', encoding="ISO-8859-1") as cf:
                        cidrs = cf.readlines()
                        for cidr in cidrs:
                            try:
                                if ipaddress.ip_address(ipd) in ipaddress.ip_network(cidr):
                                   destination = kenzerdb+cidr.replace("/","#")
                                   break
                            except:
                                continue
                if not os.path.exists(destination):
                    continue
                with open(destination+"/urlenum.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(subdomain)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/urlenum.kenz"))
                os.system("rm {0}.old".format(destination+"/urlenum.kenz"))
            except:
                continue
        return

    # normalizes headenum
    def norm_headenum(self):
        kenzerdb = self.db
        headenum = self.path+"/headenum.kenz"
        if(os.path.exists(headenum) == False):
            return
        with open(headenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[0]
                if len(subdomain)<=0:
                    continue
                extracted = tldextract.extract(subdomain)
                domain = "{0}.{1}".format(extracted.domain, extracted.suffix)
                subdo = "{0}.{1}.{2}".format(extracted.subdomain, extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    try:
                        ipd = socket.gethostbyname(subdo.lower().strip("."))
                    except:
                        continue
                    with open(kenzerdb+"../summary/cidr.txt", 'r', encoding="ISO-8859-1") as cf:
                        cidrs = cf.readlines()
                        for cidr in cidrs:
                            try:
                                if ipaddress.ip_address(ipd) in ipaddress.ip_network(cidr):
                                   destination = kenzerdb+cidr.replace("/","#")
                                   break
                            except:
                                continue
                if not os.path.exists(destination):
                    continue
                if subdomain.strip() != domain:
                    os.system("ex +g/\"{0}\"/d -cwq {1}".format(subdomain.strip(), destination+"/headenum.kenz"))
                with open(destination+"/headenum.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/headenum.kenz"))
                os.system("rm {0}.old".format(destination+"/headenum.kenz"))
            except:
                continue
        return
    
    # normalizes wafscan
    def norm_wafscan(self):
        kenzerdb = self.db
        wafscan = self.path+"/wafscan.kenz"
        if(os.path.exists(wafscan) == False):
            return
        with open(wafscan, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(",")[0]
                if len(subdomain)<=0:
                    continue
                extracted = tldextract.extract(subdomain)
                domain = "{0}.{1}".format(extracted.domain, extracted.suffix)
                subdo = "{0}.{1}.{2}".format(extracted.subdomain, extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    try:
                        ipd = socket.gethostbyname(subdo.lower().strip("."))
                    except:
                        continue
                    with open(kenzerdb+"../summary/cidr.txt", 'r', encoding="ISO-8859-1") as cf:
                        cidrs = cf.readlines()
                        for cidr in cidrs:
                            try:
                                if ipaddress.ip_address(ipd) in ipaddress.ip_network(cidr):
                                   destination = kenzerdb+cidr.replace("/","#")
                                   break
                            except:
                                continue
                if not os.path.exists(destination):
                    continue
                if subdomain.strip() != domain:
                    os.system("ex +g/\"{0}\"/d -cwq {1}".format(subdomain.strip(), destination+"/wafscan.kenz"))
                with open(destination+"/wafscan.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/wafscan.kenz"))
                os.system("rm {0}.old".format(destination+"/wafscan.kenz"))
            except:
                continue
        return

    # normalizes shodscan
    def norm_shodscan(self):
        kenzerdb = self.db
        shodscan = self.path+"/shodscan.kenz"
        if(os.path.exists(shodscan) == False):
            return
        with open(shodscan, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[0]
                if len(subdomain)<=0:
                    continue
                extracted = tldextract.extract(subdomain)
                domain = "{0}.{1}".format(extracted.domain, extracted.suffix)
                subdo = "{0}.{1}.{2}".format(extracted.subdomain, extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    try:
                        ipd = socket.gethostbyname(subdo.lower().strip("."))
                    except:
                        continue
                    with open(kenzerdb+"../summary/cidr.txt", 'r', encoding="ISO-8859-1") as cf:
                        cidrs = cf.readlines()
                        for cidr in cidrs:
                            try:
                                if ipaddress.ip_address(ipd) in ipaddress.ip_network(cidr):
                                   destination = kenzerdb+cidr.replace("/","#")
                                   break
                            except:
                                continue
                if not os.path.exists(destination):
                    continue
                if subdomain.strip() != domain:
                    os.system("ex +g/\"{0}\"/d -cwq {1}".format(subdomain.strip(), destination+"/shodscan.kenz"))
                with open(destination+"/shodscan.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/shodscan.kenz"))
                os.system("rm {0}.old".format(destination+"/shodscan.kenz"))
            except:
                continue
        return

    # normalizes asnenum
    def norm_asnenum(self):
        kenzerdb = self.db
        asnenum = self.path+"/asnenum.kenz"
        if(os.path.exists(asnenum) == False):
            return
        with open(asnenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[0]
                if len(subdomain)<=0:
                    continue
                extracted = tldextract.extract(subdomain)
                domain = "{0}.{1}".format(extracted.domain, extracted.suffix)
                subdo = "{0}.{1}.{2}".format(extracted.subdomain, extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    try:
                        ipd = socket.gethostbyname(subdo.lower().strip("."))
                    except:
                        continue
                    with open(kenzerdb+"../summary/cidr.txt", 'r', encoding="ISO-8859-1") as cf:
                        cidrs = cf.readlines()
                        for cidr in cidrs:
                            try:
                                if ipaddress.ip_address(ipd) in ipaddress.ip_network(cidr):
                                   destination = kenzerdb+cidr.replace("/","#")
                                   break
                            except:
                                continue
                if not os.path.exists(destination):
                    continue
                if subdomain.strip() != domain:
                    os.system("ex +g/\"{0}\"/d -cwq {1}".format(subdomain.strip(), destination+"/asnenum.kenz"))
                with open(destination+"/asnenum.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/asnenum.kenz"))
                os.system("rm {0}.old".format(destination+"/asnenum.kenz"))
            except:
                continue
        return

    # normalizes dnsenum
    def norm_dnsenum(self):
        kenzerdb = self.db
        dnsenum = self.path+"/dnsenum.kenz"
        if(os.path.exists(dnsenum) == False):
            return
        with open(dnsenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1]
                if len(subdomain)<=0:
                    continue
                extracted = tldextract.extract(subdomain)
                domain = "{0}.{1}".format(extracted.domain, extracted.suffix)
                subdo = "{0}.{1}.{2}".format(extracted.subdomain, extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    try:
                        ipd = socket.gethostbyname(subdo.lower().strip("."))
                    except:
                        continue
                    with open(kenzerdb+"../summary/cidr.txt", 'r', encoding="ISO-8859-1") as cf:
                        cidrs = cf.readlines()
                        for cidr in cidrs:
                            try:
                                if ipaddress.ip_address(ipd) in ipaddress.ip_network(cidr):
                                   destination = kenzerdb+cidr.replace("/","#")
                                   break
                            except:
                                continue
                if not os.path.exists(destination):
                    continue
                if subdomain.strip() != domain:
                    os.system("ex +g/\"{0}\"/d -cwq {1}".format(subdomain.strip(), destination+"/dnsenum.kenz"))
                with open(destination+"/dnsenum.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/dnsenum.kenz"))
                os.system("rm {0}.old".format(destination+"/dnsenum.kenz"))
            except:
                continue
        return

    # normalizes favscan
    def norm_favscan(self):
        kenzerdb = self.db
        favscan = self.path+"/favscan.kenz"
        if(os.path.exists(favscan) == False):
            return
        with open(favscan, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split("	")[2]
                if len(subdomain)<=0:
                    continue
                extracted = tldextract.extract(subdomain)
                domain = "{0}.{1}".format(extracted.domain, extracted.suffix)
                subdo = "{0}.{1}.{2}".format(extracted.subdomain, extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    try:
                        ipd = socket.gethostbyname(subdo.lower().strip("."))
                    except:
                        continue
                    with open(kenzerdb+"../summary/cidr.txt", 'r', encoding="ISO-8859-1") as cf:
                        cidrs = cf.readlines()
                        for cidr in cidrs:
                            try:
                                if ipaddress.ip_address(ipd) in ipaddress.ip_network(cidr):
                                   destination = kenzerdb+cidr.replace("/","#")
                                   break
                            except:
                                continue
                if not os.path.exists(destination):
                    continue
                if subdomain.strip() != domain:
                    os.system("ex +g/\"{0}\"/d -cwq {1}".format(subdomain.strip(), destination+"/favscan.kenz"))
                with open(destination+"/favscan.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/favscan.kenz"))
                os.system("rm {0}.old".format(destination+"/favscan.kenz"))
            except:
                continue
        return

    # normalizes conenum
    def norm_conenum(self):
        kenzerdb = self.db
        conenum = self.path+"/conenum.kenz"
        if(os.path.exists(conenum) == False):
            return
        with open(conenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split("]")[1].split(" ")[1]
                if len(subdomain)<=0:
                    continue
                extracted = tldextract.extract(subdomain)
                domain = "{0}.{1}".format(extracted.domain, extracted.suffix)
                subdo = "{0}.{1}.{2}".format(extracted.subdomain, extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    try:
                        ipd = socket.gethostbyname(subdo.lower().strip("."))
                    except:
                        continue
                    with open(kenzerdb+"../summary/cidr.txt", 'r', encoding="ISO-8859-1") as cf:
                        cidrs = cf.readlines()
                        for cidr in cidrs:
                            try:
                                if ipaddress.ip_address(ipd) in ipaddress.ip_network(cidr):
                                   destination = kenzerdb+cidr.replace("/","#")
                                   break
                            except:
                                continue
                if not os.path.exists(destination):
                    continue
                with open(destination+"/conenum.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/conenum.kenz"))
                os.system("rm {0}.old".format(destination+"/conenum.kenz"))
            except:
                continue
        return

    # normalizes socenum
    def norm_socenum(self):
        kenzerdb = self.db
        socenum = self.path+"/socenum.kenz"
        if(os.path.exists(socenum) == False):
            return
        with open(socenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1].replace("[","").replace("]","")
                if len(subdomain)<=0:
                    continue
                extracted = tldextract.extract(subdomain)
                domain = "{0}.{1}".format(extracted.domain, extracted.suffix)
                subdo = "{0}.{1}.{2}".format(extracted.subdomain, extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    try:
                        ipd = socket.gethostbyname(subdo.lower().strip("."))
                    except:
                        continue
                    with open(kenzerdb+"../summary/cidr.txt", 'r', encoding="ISO-8859-1") as cf:
                        cidrs = cf.readlines()
                        for cidr in cidrs:
                            try:
                                if ipaddress.ip_address(ipd) in ipaddress.ip_network(cidr):
                                   destination = kenzerdb+cidr.replace("/","#")
                                   break
                            except:
                                continue
                if not os.path.exists(destination):
                    continue
                with open(destination+"/socenum.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/socenum.kenz"))
                os.system("rm {0}.old".format(destination+"/socenum.kenz"))
            except:
                continue
        return

    # normalizes keysenum
    def norm_keysenum(self):
        kenzerdb = self.db
        keysenum = self.path+"/keysenum.kenz"
        if(os.path.exists(keysenum) == False):
            return
        with open(keysenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1].replace("[","").replace("]","")
                if len(subdomain)<=0:
                    continue
                extracted = tldextract.extract(subdomain)
                domain = "{0}.{1}".format(extracted.domain, extracted.suffix)
                subdo = "{0}.{1}.{2}".format(extracted.subdomain, extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    try:
                        ipd = socket.gethostbyname(subdo.lower().strip("."))
                    except:
                        continue
                    with open(kenzerdb+"../summary/cidr.txt", 'r', encoding="ISO-8859-1") as cf:
                        cidrs = cf.readlines()
                        for cidr in cidrs:
                            try:
                                if ipaddress.ip_address(ipd) in ipaddress.ip_network(cidr):
                                   destination = kenzerdb+cidr.replace("/","#")
                                   break
                            except:
                                continue
                if not os.path.exists(destination):
                    continue
                with open(destination+"/keysenum.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/keysenum.kenz"))
                os.system("rm {0}.old".format(destination+"/keysenum.kenz"))
            except:
                continue
        return

    # normalizes servenum
    def norm_servenum(self):
        kenzerdb = self.db
        servenum = self.path+"/servenum.kenz"
        if(os.path.exists(servenum) == False):
            return
        with open(servenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1]
                if len(subdomain)<=0:
                    continue
                extracted = tldextract.extract(subdomain)
                domain = "{0}.{1}".format(extracted.domain, extracted.suffix)
                subdo = "{0}.{1}.{2}".format(extracted.subdomain, extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    try:
                        ipd = socket.gethostbyname(subdo.lower().strip("."))
                    except:
                        continue
                    with open(kenzerdb+"../summary/cidr.txt", 'r', encoding="ISO-8859-1") as cf:
                        cidrs = cf.readlines()
                        for cidr in cidrs:
                            try:
                                if ipaddress.ip_address(ipd) in ipaddress.ip_network(cidr):
                                   destination = kenzerdb+cidr.replace("/","#")
                                   break
                            except:
                                continue
                if not os.path.exists(destination):
                    continue
                with open(destination+"/servenum.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/servenum.kenz"))
                os.system("rm {0}.old".format(destination+"/servenum.kenz"))
            except:
                continue
        return

    # normalizes repenum
    def norm_repenum(self):
        kenzerdb = self.db
        repenum = self.path+"/repenum.kenz"
        if(os.path.exists(repenum) == False):
            return
        with open(repenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1]
                if len(subdomain)<=0:
                    continue
                extracted = tldextract.extract(subdomain)
                domain = "{0}.{1}".format(extracted.domain, extracted.suffix)
                subdo = "{0}.{1}.{2}".format(extracted.subdomain, extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    try:
                        ipd = socket.gethostbyname(subdo.lower().strip("."))
                    except:
                        continue
                    with open(kenzerdb+"../summary/cidr.txt", 'r', encoding="ISO-8859-1") as cf:
                        cidrs = cf.readlines()
                        for cidr in cidrs:
                            try:
                                if ipaddress.ip_address(ipd) in ipaddress.ip_network(cidr):
                                   destination = kenzerdb+cidr.replace("/","#")
                                   break
                            except:
                                continue
                if not os.path.exists(destination):
                    continue
                if subdomain.strip() != domain:
                    os.system("ex +g/\"{0}\"/d -cwq {1}".format(subdomain.strip(), destination+"/repenum.kenz"))
                with open(destination+"/repenum.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/repenum.kenz"))
                os.system("rm {0}.old".format(destination+"/repenum.kenz"))
            except:
                continue
        return

    # normalizes idscan
    def norm_idscan(self):
        kenzerdb = self.db
        idscan = self.path+"/idscan.kenz"
        if(os.path.exists(idscan) == False):
            return
        with open(idscan, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1]
                if len(subdomain)<=0:
                    continue
                extracted = tldextract.extract(subdomain)
                domain = "{0}.{1}".format(extracted.domain, extracted.suffix)
                subdo = "{0}.{1}.{2}".format(extracted.subdomain, extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    try:
                        ipd = socket.gethostbyname(subdo.lower().strip("."))
                    except:
                        continue
                    with open(kenzerdb+"../summary/cidr.txt", 'r', encoding="ISO-8859-1") as cf:
                        cidrs = cf.readlines()
                        for cidr in cidrs:
                            try:
                                if ipaddress.ip_address(ipd) in ipaddress.ip_network(cidr):
                                   destination = kenzerdb+cidr.replace("/","#")
                                   break
                            except:
                                continue
                if not os.path.exists(destination):
                    continue
                with open(destination+"/idscan.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/idscan.kenz"))
                os.system("rm {0}.old".format(destination+"/idscan.kenz"))
            except:
                continue
        return
    
    # normalizes xssscan
    def norm_xssscan(self):
        kenzerdb = self.db
        xssscan = self.path+"/xssscan.kenz"
        if(os.path.exists(xssscan) == False):
            return
        with open(xssscan, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1]
                if len(subdomain)<=0:
                    continue
                extracted = tldextract.extract(subdomain)
                domain = "{0}.{1}".format(extracted.domain, extracted.suffix)
                subdo = "{0}.{1}.{2}".format(extracted.subdomain, extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    try:
                        ipd = socket.gethostbyname(subdo.lower().strip("."))
                    except:
                        continue
                    with open(kenzerdb+"../summary/cidr.txt", 'r', encoding="ISO-8859-1") as cf:
                        cidrs = cf.readlines()
                        for cidr in cidrs:
                            try:
                                if ipaddress.ip_address(ipd) in ipaddress.ip_network(cidr):
                                   destination = kenzerdb+cidr.replace("/","#")
                                   break
                            except:
                                continue
                if not os.path.exists(destination):
                    continue
                with open(destination+"/xssscan.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/xssscan.kenz"))
                os.system("rm {0}.old".format(destination+"/xssscan.kenz"))
            except:
                continue
        return

    # normalizes vulnscan
    def norm_vulnscan(self):
        kenzerdb = self.db
        vulnscan = self.path+"/vulnscan.kenz"
        if(os.path.exists(vulnscan) == False):
            return
        with open(vulnscan, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1]
                if len(subdomain)<=0:
                    continue
                extracted = tldextract.extract(subdomain)
                domain = "{0}.{1}".format(extracted.domain, extracted.suffix)
                subdo = "{0}.{1}.{2}".format(extracted.subdomain, extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    try:
                        ipd = socket.gethostbyname(subdo.lower().strip("."))
                    except:
                        continue
                    with open(kenzerdb+"../summary/cidr.txt", 'r', encoding="ISO-8859-1") as cf:
                        cidrs = cf.readlines()
                        for cidr in cidrs:
                            try:
                                if ipaddress.ip_address(ipd) in ipaddress.ip_network(cidr):
                                   destination = kenzerdb+cidr.replace("/","#")
                                   break
                            except:
                                continue
                if not os.path.exists(destination):
                    continue
                with open(destination+"/vulnscan.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/vulnscan.kenz"))
                os.system("rm {0}.old".format(destination+"/vulnscan.kenz"))
            except:
                continue
        return

    # normalizes subscan
    def norm_subscan(self):
        kenzerdb = self.db
        subscan = self.path+"/subscan.kenz"
        if(os.path.exists(subscan) == False):
            return
        with open(subscan, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1]
                if len(subdomain)<=0:
                    continue
                extracted = tldextract.extract(subdomain)
                domain = "{0}.{1}".format(extracted.domain, extracted.suffix)
                subdo = "{0}.{1}.{2}".format(extracted.subdomain, extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    try:
                        ipd = socket.gethostbyname(subdo.lower().strip("."))
                    except:
                        continue
                    with open(kenzerdb+"../summary/cidr.txt", 'r', encoding="ISO-8859-1") as cf:
                        cidrs = cf.readlines()
                        for cidr in cidrs:
                            try:
                                if ipaddress.ip_address(ipd) in ipaddress.ip_network(cidr):
                                   destination = kenzerdb+cidr.replace("/","#")
                                   break
                            except:
                                continue
                if not os.path.exists(destination):
                    continue
                with open(destination+"/subscan.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/subscan.kenz"))
                os.system("rm {0}.old".format(destination+"/subscan.kenz"))
            except:
                continue
        return

    # normalizes cscan
    def norm_cscan(self):
        kenzerdb = self.db
        cscan = self.path+"/cscan.kenz"
        if(os.path.exists(cscan) == False):
            return
        with open(cscan, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1]
                if len(subdomain)<=0:
                    continue
                extracted = tldextract.extract(subdomain)
                domain = "{0}.{1}".format(extracted.domain, extracted.suffix)
                subdo = "{0}.{1}.{2}".format(extracted.subdomain, extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    try:
                        ipd = socket.gethostbyname(subdo.lower().strip("."))
                    except:
                        continue
                    with open(kenzerdb+"../summary/cidr.txt", 'r', encoding="ISO-8859-1") as cf:
                        cidrs = cf.readlines()
                        for cidr in cidrs:
                            try:
                                if ipaddress.ip_address(ipd) in ipaddress.ip_network(cidr):
                                   destination = kenzerdb+cidr.replace("/","#")
                                   break
                            except:
                                continue
                if not os.path.exists(destination):
                    continue
                with open(destination+"/cscan.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/cscan.kenz"))
                os.system("rm {0}.old".format(destination+"/cscan.kenz"))
            except:
                continue
        return

    # normalizes cvescan
    def norm_cvescan(self):
        kenzerdb = self.db
        cvescan = self.path+"/cvescan.kenz"
        if(os.path.exists(cvescan) == False):
            return
        with open(cvescan, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1]
                if len(subdomain)<=0:
                    continue
                extracted = tldextract.extract(subdomain)
                domain = "{0}.{1}".format(extracted.domain, extracted.suffix)
                subdo = "{0}.{1}.{2}".format(extracted.subdomain, extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    try:
                        ipd = socket.gethostbyname(subdo.lower().strip("."))
                    except:
                        continue
                    with open(kenzerdb+"../summary/cidr.txt", 'r', encoding="ISO-8859-1") as cf:
                        cidrs = cf.readlines()
                        for cidr in cidrs:
                            try:
                                if ipaddress.ip_address(ipd) in ipaddress.ip_network(cidr):
                                   destination = kenzerdb+cidr.replace("/","#")
                                   break
                            except:
                                continue
                if not os.path.exists(destination):
                    continue
                with open(destination+"/cvescan.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/cvescan.kenz"))
                os.system("rm {0}.old".format(destination+"/cvescan.kenz"))
            except:
                continue
        return

    # normalizes buckscan
    def norm_buckscan(self):
        kenzerdb = self.db
        buckscan = self.path+"/buckscan.kenz"
        if(os.path.exists(buckscan) == False):
            return
        with open(buckscan, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1]
                if len(subdomain)<=0:
                    continue
                extracted = tldextract.extract(subdomain)
                domain = "{0}.{1}".format(extracted.domain, extracted.suffix)
                subdo = "{0}.{1}.{2}".format(extracted.subdomain, extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    try:
                        ipd = socket.gethostbyname(subdo.lower().strip("."))
                    except:
                        continue
                    with open(kenzerdb+"../summary/cidr.txt", 'r', encoding="ISO-8859-1") as cf:
                        cidrs = cf.readlines()
                        for cidr in cidrs:
                            try:
                                if ipaddress.ip_address(ipd) in ipaddress.ip_network(cidr):
                                   destination = kenzerdb+cidr.replace("/","#")
                                   break
                            except:
                                continue
                if not os.path.exists(destination):
                    continue
                with open(destination+"/buckscan.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/buckscan.kenz"))
                os.system("rm {0}.old".format(destination+"/buckscan.kenz"))
            except:
                continue
        return

    # normalizes vizscan
    def norm_vizscan(self):
        kenzerdb = self.db
        vizscan = self.path+"/vizscan.kenz"
        if(os.path.exists(vizscan) == False):
            return
        with open(vizscan, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[2].replace("_","/")
                if len(subdomain)<=0:
                    continue
                extracted = tldextract.extract(subdomain)
                domain = "{0}.{1}".format(extracted.domain, extracted.suffix)
                subdo = "{0}.{1}.{2}".format(extracted.subdomain, extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    try:
                        ipd = socket.gethostbyname(subdo.lower().strip("."))
                    except:
                        continue
                    with open(kenzerdb+"../summary/cidr.txt", 'r', encoding="ISO-8859-1") as cf:
                        cidrs = cf.readlines()
                        for cidr in cidrs:
                            try:
                                if ipaddress.ip_address(ipd) in ipaddress.ip_network(cidr):
                                   destination = kenzerdb+cidr.replace("/","#")
                                   break
                            except:
                                continue
                if not os.path.exists(destination):
                    continue
                if subdomain.strip() != domain:
                    os.system("ex +g/\"{0}\"/d -cwq {1}".format(subdomain.strip(), destination+"/vizscan.kenz"))
                with open(destination+"/vizscan.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                if not os.path.exists(destination+"/vizscan"):
                    os.system("mkdir "+destination+"/vizscan")
                os.system("mv {0} {1}".format(self.path+"/vizscan/*"+domain+"*.png", destination+"/vizscan/" ))
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/vizscan.kenz"))
                os.system("rm {0}.old".format(destination+"/vizscan.kenz"))
            except:
                continue
        return