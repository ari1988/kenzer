<div align='left'><p><h2>KENZER - Automated web assets enumeration & scanning</h2><div id='badges'><a href='https://www.linkedin.com/company/scanfactory-io'><img src='https://img.shields.io/badge/LinkedIn-black?style=for-the-badge&logo=linkedin&logoColor=white' alt='ScanFactory LinkedIn'/></a> <a href='https://twitter.com/scanfactory_io'><img src='https://img.shields.io/badge/Twitter-black?style=for-the-badge&logo=twitter&logoColor=white' alt='ScanFactory Twitter'/></a> <a href='https://t.me/scanfactorybot'><img src='https://img.shields.io/badge/Telegram Recon Bot-black?style=for-the-badge&logo=telegram&logoColor=white' alt='ScanFactory Telegram Recon Bot'/></a></div></p></div>

## Mentions

[A Conceptual Introduction to Automating Bug Bounties](https://g147.medium.com/a-conceptual-introduction-to-automating-bug-bounties-ft-arpsyndicate-yeswehack-scanfactory-f2468f345d7)<br>

## Demo

[![kenzer](screenshots/yt-thumbnail.png)](https://www.youtube.com/watch?v=pD0IRloikz8)

## Screenshots

![kenzer](screenshots/kenzer0.png)
![kenzer](screenshots/kenzer1.png)

## Instructions for running

0. Run `git clone https://github.com/ARPSyndicate/kenzer /root/kenzer && cd /root/kenzer` **(preferred)**<br>
1. Create an account on [Zulip](https://zulipchat.com)<br>
2. Navigate to `Settings > Your Bots > Add a new bot`<br>
3. Create a new generic bot named `kenzer`<br>
4. Add all the configurations in `configs/kenzer.conf`<br>
5. Install/Run using - <br>
   - `./install.sh -b` [if you need `kenzer-compatible` binaries to be installed] **(preferred)**<br>
   - `./install.sh` [if you do not need `kenzer-compatible` binaries to be installed]<br>
   - `./run.sh` [if you do not need installation at all]<br>
   - `./service.sh` [initialize it as a service post-installation] **(preferred)**<br>
   - `bash swap.sh` [in case you are facing memory issues]
6. Interact with `kenzer` using Zulip client, by adding bot to a stream or via DM.<br>
7. Test `@**kenzer** man` as Zulip input to display available commands.<br>
8. All the commands can be used by mentioning the chatbot using the prefix `@**kenzer**` (name of your chatbot).<br>

## Some Popular Features
- Subdomain Enumeration using Subfinder, Amass, CerteX, TLSX, DNSX, NXScan, & ShuffleDNS
- Port Enumeration using NXScan (Shodan, Netlas, Naabu & Nmap)
- Web Enumeration using HttpX, Favinizer, Domlock, Gau, GoSpider, URLhunter & Waymore
- Web Vulnerability Scanning using Jaeles, Wapiti, ZAP, Nuclei, Rescro & DalFox
- Backup Files Scanning using Fuzzuli
- Git Repository Enumeration & Scanning using RepoHunt & Trufflehog
- Web Screenshot Identification using Shottie & Perceptic
- WAF Detection & Avoidance using WafW00f & Nuclei
- Reputation Scoring using DomREP (GreyNoise, URLHaus, PhishTank)
- Every task can be distributed over multiple machines

## Built-in Modules

> - `blacklist <target>,<regex>` - initializes & removes blacklisted targets
> - `whitelist <target>,<regex>` - initializes & keeps only whitelisted targets
> - `program <target>,[<name>][<meta>][<link>]` - initializes the program to which target belongs
> - `subenum[-<mode>[active/passive (default=all)]] <target>` - enumerates subdomains
> - `repenum <target>` - enumerates reputation of subdomains
> - `repoenum <target>` - enumerates github repositories
> - `portenum[-<mode>[100/1000/full/fast (default=1000)]] <target>` - enumerates open ports
> - `servenum <target>` - enumerates services
> - `webenum <target>` - enumerates webservers
> - `headenum <target>` - enumerates additional info from webservers
> - `urlheadenum <target>` - enumerates additional info from urls
> - `asnenum <target>` - enumerates asn records
> - `dnsenum <target>` - enumerates dns records
> - `conenum <target>` - enumerates hidden files & directories
> - `urlenum[-<mode>[active/passive (default=all)]] <target>` - enumerates urls
> - `socenum <target>` - enumerates social media accounts
> - `keysenum <target>` - enumerates sensitive api keys
> - `wafscan <target>` - scans for firewalls
> - `subscan[-<mode>[web/dns (default=all)]] <target>` - hunts for subdomain takeovers
> - `urlscan[-<mode>[cmdi/crlf/redirect/sqli/ssrf/ssti/xss (default=all)]] <target>` - hunts for vulnerabilities in URL parameters
> - `reposcan <target>` - scans github repositories for api key leaks
> - `bakscan <target>` - scans for backup files
> - `cscan[-<severity>[critical/high/medium/low/info/workflow (default=all)]] <target>` - scan with customized templates
> - `cvescan[-<severity>[critical/high/medium/low/info/workflow (default=all)]] <target>` - hunts for CVEs
> - `vulnscan[-<severity>[critical/high/medium/low/info/workflow (default=all)]] <target>` - hunts for other common vulnerabilities
> - `idscan[-<severity>[critical/high/medium/low/info/workflow (default=all)]] <target>` - identifies applications running on webservers
> - `portscan <target>` - scans open ports (nmap)(slow)
> - `shodscan <target>` - scans open ports (shodan)(fast)
> - `xssscan <target>` - scans for xss vulnerabilities
> - `appscan <target>` - scans for webapp vulnerabilities
> - `buckscan <target>` - hunts for unreferenced aws s3 buckets
> - `favscan <target>` - fingerprints webservers using favicon
> - `vizscan[-<mode>[web/repo (default=web)]] <target>` - screenshots websites & repositories
> - `enum <target>` - runs all enumerator modules
> - `scan <target>` - runs all scanner modules
> - `recon <target>` - runs all modules
> - `hunt <target>` - runs your custom workflow
> - `disseminate <command> <target>` - splits & distributes input over multiple bots
> - `upload` - switches upload functionality
> - `waf` - switches waf avoid functionality"
> - `upgrade` - upgrades kenzer to latest version
> - `monitor <target>` - monitors ct logs for new subdomains
> - `monitor normalize` - normalizes the enumerations from ct logs
> - `monitor db` - monitors ct logs for domains in summary/domain.txt
> - `monitor autohunt <frequency(default=5)>` - starts automated hunt while monitoring
> - `sync` - synchronizes the local kenzerdb with github
> - `freaker <module> [<target>]` - runs freaker module
> - `kenzer <module>` - runs a specific module
> - `kenzer man` - shows this manual

## The Beginner's Workflow

![workflow](screenshots/workflow.png)

Although few more modules are available & much more is going to be released in the course of time which can advance this workflow, yet this one is enough to get started with & listed below are few of its successful hunts.<br><br>
<img src="screenshots/adobe.png" width="200" height="60">
<img src="screenshots/ibm.png" width="150" height="60">
<img src="screenshots/amazon.png" width="150" height="50">
<img src="screenshots/algolia.png" width="250" height="60">

**COMPATIBILITY TESTED ON UBUNTU 20.04.5 (x86_64) ONLY**<br>
**RIGGED WITH LOGIC ISSUES**<br>
**FEEL FREE TO SUBMIT PULL REQUESTS**<br>
**THIS IS A VERY SOPHISTICATED AUTOMATION FRAMEWORK**<br>
**ABILITY TO UNDERSTAND PYTHON & BASH IS A PREREQUISITE**<br>
**WE DO NOT PROVIDE ANY SUPPORT WITH INSTALLATION**<br>
**ISSUES RELATED TO INSTALLATION WILL BE CLOSED WITHOUT ANY RESOLUTION**<br>