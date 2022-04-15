#!/usr/bin/env python
import subprocess
import multiprocessing
from multiprocessing import Process, Queue
import os
import time
import fileinput
import atexit
import sys
import socket
import re

# Todo:
# Add mysql nmap-script
# Change replace to sed:
# sed 's|literal_pattern|replacement_string|g'

start = time.time()
final_report_name = time.strftime("/root/exam/reports/final_report_%Y%m%d-%H%M%S.txt")

def myprint(s=""): 
    print s
    with open(final_report_name, "a") as f:
        f.write(s+"\n")
        f.close()


# Creates a function for multiprocessing. Several things at once.
def multProc(targetin, scanip, port):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip,port))
    jobs.append(p)
    p.start()
    return


def gobuster(ip_address, port, protocol, wordlist="/usr/share/wordlists/dirb/common.txt"):
    GOBUSTER = "gobuster -k -u %s://%s:%s -w %s -o /root/exam/reports/%s/gobuster_p%s_commonlist.txt" % (protocol, ip_address, port, wordlist, ip_address, port)
    myprint(GOBUSTER)
    results_gobuster = subprocess.check_output(GOBUSTER, shell=True)
    myprint(results_gobuster)
    myprint()
    return

def nikto(ip_address, port, url_start):
    NIKTOSCAN = "nikto -h %s://%s -o /root/exam/reports/%s/nikto-%s-%s.txt" % (url_start, ip_address, ip_address, url_start, port)
    myprint(NIKTOSCAN)
    results_nikto = subprocess.check_output(NIKTOSCAN, shell=True)
    myprint(results_nikto)
    myprint()
    return



def yasuo(ip_address, port):
    YASUOSCAN = "BUNDLE_GEMFILE=/opt/yasuo/Gemfile bundler exec /opt/yasuo/yasuo.rb -s /opt/yasuo/signatures.yaml -r %s -p %s" % (ip_address, port)
    myprint(YASUOSCAN)
    results_yasuo = subprocess.check_output(YASUOSCAN, shell=True)
    with open("/root/exam/reports/%s/yasuo_p%s.txt" % (ip_address, port),"w") as f:
        f.write(results_yasuo)
        f.close()
        
    myprint(results_yasuo)
    myprint()
    return

def wig(ip_address, port, protocol):
    WIGSCAN = "python3 /root/tools/wig/wig.py -q -a -d -w /root/exam/reports/%s/wig_p%s.txt %s://%s:%s" % (ip_address, port, protocol, ip_address, port)
    myprint(WIGSCAN)
    results_wig = subprocess.check_output(WIGSCAN, shell=True)
        
    myprint(results_wig)
    myprint()
    return



def httpEnum(ip_address, port):

    # Commented out for exam
    #gobuster_process = multiprocessing.Process(target=gobuster, args=(ip_address,port,"http"))
    #gobuster_process.start()
    #nikto_process = multiprocessing.Process(target=nikto, args=(ip_address,port,"http"))
    #nikto_process.start()
    wig_process = multiprocessing.Process(target=wig, args=(ip_address,port,"http"))
    wig_process.start()
    yasuo_process = multiprocessing.Process(target=yasuo, args=(ip_address,port))
    yasuo_process.start()


    HTTPSCAN = "nmap -sV -Pn -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,http-iis-webdav-vuln,http-php-version,http-robots.txt,http-shellshock,http-vuln-cve2015-1635 -oN /root/exam/reports/%s/%s_http.nmap %s" % (port, ip_address, ip_address, ip_address)
    
    myprint(HTTPSCAN)

    http_results = subprocess.check_output(HTTPSCAN, shell=True)
    myprint(http_results)
    myprint()

    return

def httpsEnum(ip_address, port):
    
    # Commented out for exam
    #gobuster_process = multiprocessing.Process(target=gobuster, args=(ip_address,port,"https"))
    #gobuster_process.start()
    #nikto_process = multiprocessing.Process(target=nikto, args=(ip_address,port,"https"))
    #nikto_process.start()
    wig_process = multiprocessing.Process(target=wig, args=(ip_address,port,"https"))
    wig_process.start()
    yasuo_process = multiprocessing.Process(target=yasuo, args=(ip_address,port))
    yasuo_process.start()

    # Commented out for exam
    #SSLSCAN = "sslscan %s:%s >> reports/%s/ssl_scan_%s" % (ip_address, port, ip_address, ip_address)
    #myprint(SSLSCAN)
    #ssl_results = subprocess.check_output(SSLSCAN, shell=True)

    HTTPSCANS = "nmap -sV -Pn  -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,http-iis-webdav-vuln,http-php-version,http-robots.txt,http-shellshock,http-vuln-cve2015-1635 -oN /root/exam/reports/%s/%s_http.nmap %s" % (port, ip_address, ip_address, ip_address)
    myprint(HTTPSCANS)
    https_results = subprocess.check_output(HTTPSCANS, shell=True)
    myprint(https_results)
    myprint()
    return

def mssqlEnum(ip_address, port):
    MSSQLSCAN = "nmap -sV -Pn -p %s --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes,mysql-empty-password,mysql-brute,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 --script-args=mssql.instance-port=1433,mssql.username=sa,mssql.password=sa -oN /root/exam/reports/%s/mssql_%s.nmap %s" % (port, ip_address, ip_address)
    myprint(MSSQLSCAN)
    mssql_results = subprocess.check_output(MSSQLSCAN, shell=True)
    myprint(mssql_results)
    myprint()
    return


def smtpEnum(ip_address, port):
    SMTPSCAN = "nmap -sV -Pn -p %s --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 %s -oN /root/exam/reports/%s/smtp_%s.nmap" % (port, ip_address, ip_address, ip_address)
    myprint(SMTPSCAN)
    smtp_results = subprocess.check_output(SMTPSCAN, shell=True)
    myprint(smtp_results)
    myprint()
    return

def smbNmap(ip_address, port):
    smbNmap = "nmap -Pn -n -p %s --script=smb-enum-shares,smb-ls,smb-enum-users,smb-mbenum,smb-os-discovery,smb-security-mode,smb-vuln-cve2009-3103,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-regsvc-dos %s -oN /root/exam/reports/%s/smb_%s.nmap" % (port, ip_address, ip_address, ip_address)
    smbNmap_results = subprocess.check_output(smbNmap, shell=True)
    myprint(smbNmap_results)
    myprint()
    return

def smbEnum(ip_address, port):
    enum4linux = "enum4linux -a %s > /root/exam/reports/%s/enum4linux_%s 2>/dev/null" % (ip_address, ip_address, ip_address)
    enum4linux_results = subprocess.check_output(enum4linux, shell=True)
    myprint(enum4linux_results)
    myprint()
    return

def ftpEnum(ip_address, port):
    FTPSCAN = "nmap -sV -Pn -p %s --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN '/root/exam/reports/%s/ftp_%s.nmap' %s" % (port, ip_address, ip_address, ip_address)
    myprint(FTPSCAN)
    results_ftp = subprocess.check_output(FTPSCAN, shell=True)
    myprint(results_ftp)
    myprint()
    return

def udpScan(ip_address):
    UDPSCAN = "nmap -Pn -n  -sC -sU -T 3 --max-retries=2 --top-ports 200 -oN '/root/exam/reports/%s/udp_%s.nmap' %s"  % (ip_address, ip_address, ip_address)
    myprint(UDPSCAN)
    udpscan_results = subprocess.check_output(UDPSCAN, shell=True)
    myprint(udpscan_results)
    # Commented out for exam
    #UNICORNSCAN = "unicornscan -mU -I %s > /root/exam/reports/%s/unicorn_udp_%s.txt" % (ip_address, ip_address, ip_address)
    #unicornscan_results = subprocess.check_output(UNICORNSCAN, shell=True)
    myprint()

def sshScan(ip_address, port):
    SSHSCAN = "nmap -sV -Pn -p %s --script=ssh-auth-methods,ssh-hostkey,ssh-run,sshv1 -oN '/root/exam/reports/%s/ssh_%s.nmap' %s" % (port, ip_address, ip_address, ip_address)
    myprint(SSHSCAN)
    results_ssh = subprocess.check_output(SSHSCAN, shell=True)
    myprint(results_ssh)
    return

def pop3Scan(ip_address, port):
    POP3SCAN = "nmap -sV -Pn -p %s --script=pop3-brute,pop3-capabilities,pop3-ntlm-info -oN '/root/exam/reports/%s/pop3_%s.nmap' %s" % (port, ip_address, ip_address, ip_address)
    myprint(SSHSCAN)
    results_pop3 = subprocess.check_output(POP3SCAN, shell=True)
    myprint(results_pop3)
    return

def searchsploit(ip_address):
    SEARCHSPLOIT = "searchsploit --nmap reports/%s/TCP%s.xml --color" % (ip_address, ip_address) 
    results_searchsploit = subprocess.check_output(SEARCHSPLOIT, shell=True)
    with open("/root/exam/reports/%s/searchsploit.txt" % (ip_address), "w") as f:
        f.write(results_searchsploit)
        f.close()

    myprint(results_searchsploit)
    myprint()

def nmapScan(ip_address):
    ip_address = ip_address.strip()

    TCPSCAN = "nmap -Pn -n -sSV -p0-65535 --max-retries=1 -T4  %s -oA '/root/exam/reports/%s/TCP%s'"  % (ip_address, ip_address, ip_address)
    myprint(TCPSCAN)
    results = subprocess.check_output(TCPSCAN, shell=True)
    myprint(results)
    myprint()

    p = multiprocessing.Process(target=udpScan, args=(scanip,))
    p.start()


    # Do Searchsploit parsing of nmap xml file
    # Uncommented for exam
    #p_searchsploit = multiprocessing.Process(target=searchsploit, args=(scanip,))
    #p_searchsploit.start()

    lines = results.split("\n")
    serv_dict = {}
    for line in lines:
        ports = []
        line = line.strip()
        if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
            # myprint( line
            while "  " in line:
                line = line.replace("  ", " ");
            linesplit= line.split(" ")
            service = linesplit[2] # grab the service name

            port = line.split(" ")[0] # grab the port/proto
            # myprint( port
            if service in serv_dict:
                ports = serv_dict[service] # if the service is already in the dict, grab the port list

            ports.append(port)
            # myprint( ports
            serv_dict[service] = ports # add service to the dictionary along with the associated port(2)



   # go through the service dictionary to call additional targeted enumeration functions
    for serv in serv_dict:
        ports = serv_dict[serv]

        #if re.search(r"http[^s]", serv):
        if "http" in serv and not "https" in serv and not "ssl" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(httpEnum, ip_address, port)
        elif re.search(r"https|ssl", serv) and not "ms-wbt-server" in serv and not "imaps"  in serv and not "pop3s" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(httpsEnum, ip_address, port)
        elif "smtp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(smtpEnum, ip_address, port)
        elif "ftp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(ftpEnum, ip_address, port)
        elif ("microsoft-ds" in serv) or ("netbios-ssn" == serv):
            for port in ports:
                port = port.split("/")[0]
                multProc(smbEnum, ip_address, port)
                multProc(smbNmap, ip_address, port)
        elif "ms-sql" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(mssqlEnum, ip_address, port)
        elif "ssh" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(sshScan, ip_address, port)
        elif "snmp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(snmpEnum, ip_address, port)

    return



if len(sys.argv) < 2:
    myprint("")
    myprint("Usage: python reconscan.py <ip> <ip> <ip>")
    myprint("Example: python reconscan.py 192.168.1.101 192.168.1.102")
    myprint("")
    myprint("############################################################")
    pass
    sys.exit()


if __name__=='__main__':

    # Setting ip targets
    targets = sys.argv
    targets.pop(0)

    myprint("Targets: {}\n".format(' '.join(targets)))
    dirs = os.listdir("/root/exam/reports/")
    for scanip in targets:
        scanip = scanip.rstrip()
        if not scanip in dirs:
            subprocess.check_output("mkdir /root/exam/reports/" + scanip, shell=True)


        p = multiprocessing.Process(target=nmapScan, args=(scanip,))
        p.start()
