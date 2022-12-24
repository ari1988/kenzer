# imports
import os
import time

# scanner


class Scanner:

    # initializations
    def __init__(self, domain, db, dtype, kenzer, botn, waf, severity=""):
        self.domain = domain
        self.organization = domain
        self.severity = severity
        self.dtype = dtype
        self.botn = botn
        self.waf = waf
        if dtype:
            self.path = db+self.organization
        else:
            self.path = db+self.organization.replace("/", "#")
        self.resources = kenzer+"resources/"
        self.templates = self.resources+"kenzer-templates/"
        if(os.path.exists(self.path) == False):
            os.system("mkdir "+self.path)

    # helper modules

    # runs nuclei

    def nuclei(self, template, hosts, output):
        severity = ""
        if len(self.severity) > 0:
            severity = "/"+self.severity
        #os.system("nuclei -project -project-path {4}/nuclei -stats -retries 2 -t {3}nuclei/{0}{5} -timeout 8 -l {1} -o {2}".format(template, hosts, output, self.templates, self.path, severity))
        if severity != "/workflow":
            os.system("nuclei -stats -retries 1 -rl 50 -c 25 -duc -timeout 10 -l {1} -o {2} -t {3}nuclei/{0}{4}".format(template, hosts, output, self.templates, severity))
        else:
            os.system("cd {3}nuclei/{0} && nuclei -stats -retries 1 -rl 50 -c 25 -duc -timeout 10 -l {1} -o {2} -w workflow".format(template, hosts, output+".workflow", self.templates, severity))
            os.system("nuclei -stats -retries 1 -rl 50 -c 25 -duc -timeout 8 -l {1} -o {2} -t {3}nuclei/{0}/critical/standalone -t {3}nuclei/{0}/high/standalone -t {3}nuclei/{0}/medium/standalone -t {3}nuclei/{0}/low/standalone ".format(template, hosts, output+".standalone", self.templates, severity))
            os.system("cat {0}.* | sort -u > {0} && rm {0}.*".format(output))
        return

    # runs jaeles
    def jaeles(self, template, hosts, output):
        severity = ""
        if len(self.severity) > 0 and self.severity!= "workflow":
            severity = self.severity
        os.system("jaeles scan --retry 1 --no-background -c 50 --rootDir {3}jaeles/ -s {3}jaeles/{0}/{5} --timeout 8 -U {1} -O {2} -o {4}/jaeles --no-db --chunk true ".format(
            template, hosts, output, self.templates, self.path, severity))
        return

    # core modules

    # hunts for subdomain takeovers using nuclei
    def subscan(self):
        domain = self.domain
        path = self.path
        output = path+"/subscanWEB.log"
        subs = path+"/webenum.kenz"
        out = path+"/subscan.kenz"
        botn = self.botn
        if(os.path.exists(subs+".split."+botn)):
            subs = subs+".split."+botn
            out = out+".split."+botn
        if(os.path.exists(subs) == False):
            return("!webenum")
        self.nuclei("subscan/web", subs, output)
        subs = path+"/subenum.kenz"
        if(os.path.exists(subs+".split."+botn)):
            subs = subs+".split."+botn
        if(os.path.exists(subs) == False):
            return("!subenum")
        output = path+"/subscanDNS.log"
        self.nuclei("subscan/dns", subs, output)
        if(os.path.exists(out)):
            os.system("mv {0} {0}.old".format(out))
        os.system("cat {0}/subscan* | sort -u > {1}".format(path, out))
        line = 0
        if(os.path.exists(out)):
            with open(out, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # hunts for CVEs using nuclei & jaeles
    def cvescan(self):
        domain = self.domain
        path = self.path
        if self.waf != "True":
            subs = path+"/webenum.kenz"
            if(os.path.exists(subs) == False):
                return("!webenum")
            botn = self.botn
            out = path+"/cvescan.kenz"
            if(os.path.exists(subs+".split."+botn)):
                subs = subs+".split."+botn
                out = out+".split."+botn    
        else:
            subs = path+"/wafscan.kenz"
            if(os.path.exists(subs) == False):
                return("!wafscan")
            botn = self.botn
            out = path+"/cvescan.kenz"
            if(os.path.exists(subs+".split."+botn)):
                subs = subs+".split."+botn
                out = out+".split."+botn
            ot = path+"/wafscan.log"
            os.system("cat {0} | grep ',False,' | cut -d ',' -f 1 | sort -u > {1}".format(subs, ot))
            subs = ot
        output = path+"/cvescanDOMN.log"
        self.nuclei("cvescan", subs, output)
        output = path+"/cvescanDOMJ.log"
        self.jaeles("cvescan", subs, output)
        if(os.path.exists(out)):
            os.system("mv {0} {0}.old".format(out))
        os.system("cat {0}/cvescan* | sort -u > {1}".format(path, out))
        line = 0
        if(os.path.exists(out)):
            with open(out, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # hunts for vulnerabilities in URL parameters using nuclei & jaeles
    def urlscan(self):
        domain = self.domain
        path = self.path
        subs = path+"/urlenum.kenz"
        if(os.path.exists(subs) == False):
            return("!urlenum")
        botn = self.botn
        out = path+"/urlscan.kenz"
        if(os.path.exists(subs+".split."+botn)):
            subs = subs+".split."+botn
            out = out+".split."+botn    
        output = path+"/urlscanDOMN.log"
        self.nuclei("urlscan", subs, output)
        output = path+"/urlscanDOMJ.log"
        self.jaeles("urlscan", subs, output)
        if(os.path.exists(out)):
            os.system("mv {0} {0}.old".format(out))
        os.system("cat {0}/urlscan* | sort -u > {1}".format(path, out))
        line = 0
        if(os.path.exists(out)):
            with open(out, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # hunts for vulnerabilities using nuclei & jaeles
    def vulnscan(self):
        domain = self.domain
        path = self.path
        if self.waf != "True":
            subs = path+"/webenum.kenz"
            if(os.path.exists(subs) == False):
                return("!webenum")
            botn = self.botn
            out = path+"/vulnscan.kenz"
            if(os.path.exists(subs+".split."+botn)):
                subs = subs+".split."+botn
                out = out+".split."+botn    
        else:
            subs = path+"/wafscan.kenz"
            if(os.path.exists(subs) == False):
                return("!wafscan")
            botn = self.botn
            out = path+"/vulnscan.kenz"
            if(os.path.exists(subs+".split."+botn)):
                subs = subs+".split."+botn
                out = out+".split."+botn
            ot = path+"/wafscan.log"
            os.system("cat {0} | grep ',False,' | cut -d ',' -f 1 | sort -u > {1}".format(subs, ot))
            subs = ot
        output = path+"/vulnscanDOMN.log"
        self.nuclei("vulnscan", subs, output)
        output = path+"/vulnscanDOMJ.log"
        self.jaeles("vulnscan", subs, output)
        if(os.path.exists(out)):
            os.system("mv {0} {0}.old".format(out))
        os.system("cat {0}/vulnscan* | sort -u > {1}".format(path, out))
        line = 0
        if(os.path.exists(out)):
            with open(out, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line
    
    # scan with customized templates
    def cscan(self):
        domain = self.domain
        path = self.path
        if self.waf != "True":
            subs = path+"/webenum.kenz"
            if(os.path.exists(subs) == False):
                return("!webenum")
            botn = self.botn
            out = path+"/cscan.kenz"
            if(os.path.exists(subs+".split."+botn)):
                subs = subs+".split."+botn
                out = out+".split."+botn    
        else:
            subs = path+"/wafscan.kenz"
            if(os.path.exists(subs) == False):
                return("!wafscan")
            botn = self.botn
            out = path+"/cscan.kenz"
            if(os.path.exists(subs+".split."+botn)):
                subs = subs+".split."+botn
                out = out+".split."+botn
            ot = path+"/wafscan.log"
            os.system("cat {0} | grep ',False,' | cut -d ',' -f 1 | sort -u > {1}".format(subs, ot))
            subs = ot
        output = path+"/cscanDOMN.log"
        self.nuclei("cscan", subs, output)
        output = path+"/cscanDOMJ.log"
        self.jaeles("cscan", subs, output)
        if(os.path.exists(out)):
            os.system("mv {0} {0}.old".format(out))
        os.system("cat {0}/cscan* | sort -u > {1}".format(path, out))
        line = 0
        if(os.path.exists(out)):
            with open(out, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # hunts for unreferenced aws s3 buckets using S3Hunter
    def buckscan(self):
        domain = self.domain
        path = self.path
        subs = path+"/subenum.kenz"
        out = path+"/buckscan.kenz"
        botn = self.botn
        if(os.path.exists(subs+".split."+botn)):
            subs = subs+".split."+botn
            out = out+".split."+botn
        if(os.path.exists(subs) == False):
            return("!subenum")
        output = path+"/s3huntDirect.log"
        os.system(
            "S3Hunter -l {0} -t 10  -T 60 -o {1} --only-direct".format(subs, output))
        output = path+"/iperms.log"
        os.system(
            "S3Hunter --no-regions -l {0} -o {1} -P".format(subs, output))
        subs = output
        output = path+"/s3huntPerms.log"
        self.nuclei("subscan/web/S3Hunter.yaml", subs, output)
        if(os.path.exists(out)):
            os.system("mv {0} {0}.old".format(out))
        os.system("cat {0}/s3hunt* | sort -u > {1}".format(path, out))
        line = 0
        if(os.path.exists(out)):
            with open(out, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # fingerprints probed servers using favinizer
    def favscan(self):
        domain = self.domain
        path = self.path
        out = path+"/favscan.kenz"
        subs = path+"/webenum.kenz"
        dtype = self.dtype
        botn = self.botn
        if(os.path.exists(subs+".split."+botn)):
            subs = subs+".split."+botn
            out = out+".split."+botn
        if(os.path.exists(subs) == False):
            return("!webenum")
        if(os.path.exists(out)):
            os.system("mv {0} {0}.old".format(out))
        os.system("favinizer -d {2}/favinizer.yaml -t 8 -T 80 -l {0} -o {1}".format(subs, out, self.templates))
        if domain != "monitor" and dtype:
            os.system("mv {0} {0}.tmp && cat {0}.tmp | grep \"{1}\" | sort -u > {0} && rm {0}.tmp".format(out,domain))
        else:
            os.system("mv {0} {0}.tmp && cat {0}.tmp | sort -u > {0} && rm {0}.tmp".format(out))
        line = 0
        if(os.path.exists(out)):
            with open(out, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line
    
    # scans github repositories for api key leaks
    def reposcan(self):
        domain = self.domain
        path = self.path
        out = path+"/reposcan.kenz"
        subs = path+"/repoenum.kenz"
        if(os.path.exists(subs) == False):
            return("!repoenum")
        if(os.path.exists(out)):
            os.system("rm -r {0}/reposcan*".format(path))
        os.system(
            "mkdir {2}/reposcan && cd {2}/reposcan && for repo in `cat {0}`; do trufflehog $repo --json --cleanup | jq \".\" > \"$(echo $repo|cut -d\"/\" -f 4,5|tr \"/\" \"@\").json\" ; done && cat *.json > {1}".format(subs, out, path))
        line = 0
        if(os.path.exists(out)):
            with open(subs, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # fingerprints probed servers using nuclei & jaeles
    def idscan(self):
        domain = self.domain
        path = self.path
        if self.waf != "True":
            subs = path+"/webenum.kenz"
            if(os.path.exists(subs) == False):
                return("!webenum")
            botn = self.botn
            out = path+"/idscan.kenz"
            if(os.path.exists(subs+".split."+botn)):
                subs = subs+".split."+botn
                out = out+".split."+botn    
        else:
            subs = path+"/wafscan.kenz"
            if(os.path.exists(subs) == False):
                return("!wafscan")
            botn = self.botn
            out = path+"/idscan.kenz"
            if(os.path.exists(subs+".split."+botn)):
                subs = subs+".split."+botn
                out = out+".split."+botn
            ot = path+"/wafscan.log"
            os.system("cat {0} | grep ',False,' | cut -d ',' -f 1 | sort -u > {1}".format(subs, ot))
            subs = ot
        output = path+"/idscanDOMN.log"
        self.nuclei("idscan", subs, output)
        output = path+"/idscanDOMJ.log"
        self.jaeles("idscan", subs, output)
        if(os.path.exists(out)):
            os.system("mv {0} {0}.old".format(out))
        os.system("cat {0}/idscan* | sort -u > {1}".format(path, out))
        line = 0
        if(os.path.exists(out)):
            with open(out, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates WAFs using wafw00f & nuclei
    def wafscan(self):
        domain = self.domain
        path = self.path
        subs = path+"/webenum.kenz"
        if(os.path.exists(subs) == False):
            return("!webenum")
        output = path+"/wafscan.csv"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system("cd /root && wafw00f --no-colors -i {0} -f csv -o {1}".format(subs,output))
        out = output
        output = path+"/wafscan.kenz"
        os.system("cat {0} | grep -v 'firewall,manufacturer' | sort -u > {1}".format(out, output))
        nuout = path+"/wafscan.log"
        self.nuclei("wafscan", subs, nuout)
        allscan = []
        try:
            with open(nuout, "r") as f:
                wafscanl = f.read().splitlines()
            allscan = allscan + wafscanl
        except:
            pass
        try:
            with open(output, "r") as f:
                wafscan = f.read().splitlines()
        except:
            pass
        for rec in allscan:
            if "waf-detect" in rec:
                if rec.split(" ")[1].strip("/") not in "\n".join(wafscan):
                    wafscan.append(rec.split(" ")[1].strip("/")+",True,"+rec.split(" ")[0].split(":")[1].replace("]","")+","+rec.split(" ")[0].split(":")[1].replace("]",""))
                    continue
                for erec in range(0,len(wafscan)):
                    if "://" in rec.split(" ")[1].strip("/"):
                        if rec.split(" ")[1].strip("/")+",False," in wafscan[erec]:
                            wafscan[erec] = rec.split(" ")[1].strip("/")+",True,"+rec.split(" ")[0].split(":")[1].replace("]","")+","+rec.split(" ")[0].split(":")[1].replace("]","")
                            break
                    else:
                        if "http://"+rec.split(" ")[1].strip("/")+",False," in wafscan[erec]:
                            wafscan[erec] = "http://"+rec.split(" ")[1].strip("/")+",True,"+rec.split(" ")[0].split(":")[1].replace("]","")+","+rec.split(" ")[0].split(":")[1].replace("]","")                 
                            break
        wafscan = list(set(wafscan))
        wafscan.sort()
        with open(output, "w") as f:
            f.writelines("%s\n" % line for line in wafscan)
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line
    
    # scans for backup files using fuzzuli
    def bakscan(self):
        domain = self.domain
        path = self.path
        out = path+"/bakscan.kenz"
        outl = path+"/bakscan.log"
        subs = path+"/webenum.kenz"
        if(os.path.exists(subs) == False):
            return("!webenum")
        if(os.path.exists(out)):
            os.system("mv {0} {0}.old".format(out))
        os.system("fuzzuli -f {0} -to 15 > {1}".format(subs, outl))
        os.system('cat {0} | grep "\[-\]" | cut -d " " -f 2 | sort -u > {1}'.format(outl, out))
        line = 0
        if(os.path.exists(out)):
            with open(out, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # scans open ports using NXScan (Nmap)
    def portscan(self):
        domain = self.domain
        path = self.path
        out = path+"/portscan.kenz"
        subs = path+"/portenum.kenz"
        if(os.path.exists(subs) == False):
            return("!portenum")
        if(os.path.exists(out)):
            os.system("mv {0} {0}.old".format(out))
        os.system("sudo NXScan --only-scan -l {0} -o {1}".format(
            subs, path+"/nxscan"))
        os.system("cp {0}/scan.html {1}".format(path+"/nxscan", out))
        line = 0
        if(os.path.exists(subs)):
            with open(subs, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # scans open ports using NXScan (Shodan)
    def shodscan(self):
        domain = self.domain
        path = self.path
        out = path+"/shodscan.kenz"
        subs = path+"/subenum.kenz"
        botn = self.botn
        if(os.path.exists(subs+".split."+botn)):
            subs = subs+".split."+botn
            out = out+".split."+botn
        if(os.path.exists(subs) == False):
            return("!subenum")
        if(os.path.exists(out)):
            os.system("mv {0} {0}.old".format(out))
        os.system("sudo NXScan --only-shodan-scan -l {0} -o {1}".format(
            subs, path+"/nxscan"))
        os.system("cp {0}/shodan-scan.txt {1}".format(path+"/nxscan", out))
        line = 0
        if(os.path.exists(out)):
            with open(out, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # screenshots websites & repositories using shottie
    def vizscan(self, mode="web"):
        domain = self.domain
        path = self.path
        out = path+"/vizscan.kenz"
        if mode == "repo":
            subs = path+"/repoenum.kenz"
            log = path+"/repoenum.log" 
            if(os.path.exists(subs) == False):
                return("!repoenum")
            os.system("cp {0} {1}".format(subs, log))
            os.system("sed -i 's/$/\/search?q={0}/' {1}".format(domain, log))
            os.system("cat {0} >> {1}".format(subs, log))
            subs = log
        else:
            subs = path+"/webenum.kenz"
            if(os.path.exists(subs) == False):
                return("!webenum")
        if(os.path.exists(out)):
            os.system("rm -r {0}/vizscan*".format(path))
        os.system("shottie -l {0} -o {1}".format(subs, path+"/vizscan"))
        os.system("perceptic -s {2}perceptic.yaml -d {1}/vizscan -o {0} -t 30 && sed -i \"s/.png//g\" {0}".format(out,path, self.templates))
        os.system("while read p; do dom=`echo \"$p\" | cut -d \" \" -f 3`; sig=`echo \"$p\" | cut -d \" \" -f 1 | sed 's/\[//' | sed 's/\]//'`; ide=`echo \"$p\" | cut -d \" \" -f 2 | sed 's/\[//' | sed 's/\]//'`; mv \"{0}/vizscan/$dom.png\" \"{0}/vizscan/$sig#$ide#$dom.png\"; done < {0}/vizscan.kenz;".format(path))
        os.system("cd {0}/vizscan && optipng *".format(path))
        line = 0
        if(os.path.exists(out)):
            with open(out, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # scans for XSS vulnerabilities using DalFox
    def xssscan(self, blind=""):
        domain = self.domain
        path = self.path
        if self.waf != "True":
            subs = path+"/webenum.kenz"
            urls = path+"/urlenum.kenz"
            if(os.path.exists(subs) == False):
                return("!webenum")
            botn = self.botn
            out = path+"/xssscan.kenz"
            if(os.path.exists(subs+".split."+botn)):
                subs = subs+".split."+botn
                out = out+".split."+botn  
                urls = urls+".split."+botn
        else:
            subs = path+"/wafscan.kenz"
            urls = path+"/urlenum.kenz"
            if(os.path.exists(subs) == False):
                return("!wafscan")
            botn = self.botn
            out = path+"/xssscan.kenz"
            if(os.path.exists(subs+".split."+botn)):
                subs = subs+".split."+botn
                out = out+".split."+botn
                urls = urls+".split."+botn
            ot = path+"/wafscan.log"
            os.system("cat {0} | grep ',False,' | cut -d ',' -f 1 | sort -u > {1}".format(subs, ot))
            subs = ot
        log =  path+"/xssscan.log"
        dtype = self.dtype
        if(os.path.exists(out)):
            os.system("mv {0} {0}.old".format(out))
        os.system("cat {0} {1} | sort -u > {2}".format(subs, urls, log))
        subs=log
        if len(blind)!=0:
            os.system("dalfox file {0} --remote-payloads=portswigger,payloadbox --remote-wordlists=burp --timeout 10 -w 150 -b {2} -o {1}".format(subs, out, blind))
        else:
            os.system("dalfox file {0} --remote-payloads=portswigger,payloadbox --remote-wordlists=burp --timeout 10 -w 150 -o {1}".format(subs, out))
        line = 0
        if(os.path.exists(out)):
            with open(out, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # scans for vulnerabilities using OWASP ZAP
    def appscan(self, apikey):
        domain = self.domain
        path = self.path
        if self.waf != "True":
            subs = path+"/webenum.kenz"
            urls = path+"/urlenum.kenz"
            if(os.path.exists(subs) == False):
                return("!webenum")
            botn = self.botn
            out = path+"/appscan.kenz"
            if(os.path.exists(subs+".split."+botn)):
                subs = subs+".split."+botn
                out = out+".split."+botn  
                urls = urls+".split."+botn
        else:
            subs = path+"/wafscan.kenz"
            urls = path+"/urlenum.kenz"
            if(os.path.exists(subs) == False):
                return("!wafscan")
            botn = self.botn
            out = path+"/appscan.kenz"
            if(os.path.exists(subs+".split."+botn)):
                subs = subs+".split."+botn
                out = out+".split."+botn
                urls = urls+".split."+botn
            ot = path+"/wafscan.log"
            os.system("cat {0} | grep ',False,' | cut -d ',' -f 1 | sort -u > {1}".format(subs, ot))
            subs = ot
        if(os.path.exists(out)):
            os.system("rm {0}".format(out))
        log =  path+"/appscan.log"
        dtype = self.dtype
        os.system("cat {0} {1} | sort -u > {2}".format(subs, urls, log))
        subs=log
        os.system("zap-cli --api-key {0} -p 8077 session new".format(apikey))
        os.system("for d in `cat {0}`;do zap-cli --zap-path /usr/local/bin/zap.sh --port 8077 --api-key {1} quick-scan --spider --ajax-spider --recursive --scanners all $d; done".format(subs, apikey))
        os.system("zap-cli --zap-path /usr/local/bin/zap.sh --port 8077 --api-key {1} report -o {0}.log -f md".format(out, apikey))
        os.system("cat {0}.log >> {0} && rm {0}.log".format(out))
        line = 0
        if(os.path.exists(out)):
            with open(out, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line