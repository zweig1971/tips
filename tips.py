#!/usr/bin/python2
# -*- coding: utf-8 -*-
"""
Created on Wed Jul 16 15:38:34 2014

@author: zweig
"""

# to isntall paramiko:
# sudo apt-get install python-pip
# pip install paramiko

import os
import sys
import paramiko
import getpass
import getopt

from datetime import datetime

PFAD_datei = "/common/usr/dhcp/hosts.conf"
PFAD_monitor = "/common/usr/monitoring/bin/"
server_adress ="tsl001.acc.gsi.de"
pos_ip = 3
index=0

detec_sw ="nwt"
detec_pex="pexaria"
detec_scu="scul"
detec_expl="exploder"
detec_vme="vmel"

detec_ac ="64 bytes"
detec_al ="timeout"
detec_tr ="\x07"
datei_host="myhosts.conf"

sw_found = []
sw_active = []

# hilfe anzeigen
def help_txt():
    print "Timing IP Scanner (tips)"
    print "Duchsucht die host-datei auf der tsl001 nach dem gewuenschten geraet und"
    print "prueft ob es online ist (ping) und ob das datum lesbar ist (nicht bei den wr-switche)"
    print "arguments are :"
    print "-n  --nwt   scan all wr-switches"
    print "-p  --pex   scan all pexarias"
    print "-s  --scu   scan all scu's"
    print "-e  --expl  scan all exploder"  
    print "-v  --vme   scan all vme's"


# zugangsdaten abfragen
def logindata():
    print "Connecting the tsl001 i need your Username, Passwort and your Creditcard Nummber"
    print "--------------------------------------------------------------------------------"
    username = raw_input("Username :")
    pswd = getpass.getpass(prompt="Enter Password:")

    if username=="" or pswd=="":
        sys.exit("ERROR: invalid name or pswd")        

    return username, pswd


# datei von der tsl auf den rechner copieren
def copy_host(uname, pswd):
    print "\nConnecting tsl001..."
    try:
        t = paramiko.Transport((server_adress, 22))
        t.connect(username=uname, password=pswd)
    except Exception, e:
        sys.exit ("ACCESS DENIED")    

    print "Access granted"
    localpath =os.getcwd()+"/"+datei_host
    remotepath = PFAD_datei

    print "\ncopy file..." 
    try:
        sftp = paramiko.SFTPClient.from_transport(t)
        sftp.get(remotepath, localpath)  
    except Exception, e:
        sys.exit ("FAILURE !")    

    print "...success"


# tsloo1 verbindung aufbauen
def ssh_connect(uname, pswd):
    print "\nConnecting tsl001..."
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=server_adress, username=uname, password=pswd)
    except Exception, e:
        sys.exit ("ACCESS DENIED")

    print "Access granted"
    return ssh

    #login = "scp "+username+server_adress+":"+PFAD_datei+" "+datei_host
    #os.system(login)


def extract(detec):
    # -- datei öffnen
    print "\nopen host file "
    try:
        datei = open(datei_host, "r")
    except Exception, e:
        sys.exit ("Cant open host file")

    print "...ok"

    for line in datei:
        s=line.find(detec)
        if s > 0:
            a= line.split(",")
            sw_found.append(a[pos_ip-1])

    return sw_found


# ruft bei den scu/pex/expl/vme ein datum ab
# -> device alive & link
def alive(ssh, swac_found):
    found=[]
    i=1    
    for data in swac_found:
        print "\rCheck if unit alive %3d" % i, ('='*i)+('-'*(len(swac_found)-i)),   # status balken
        sys.stdout.flush()       
        ip, text = data.split(" ")        
        stdin, stdout, stderr = ssh.exec_command(PFAD_monitor+"eb-date udp/"+ip)        
        line=stdout.read()
        error=stderr.read()
            
        if error != "":
            print "ERROR :"+error
            found.append(data +" --ERROR:"+error)
        else :
            s=line.find(detec_al)
            if s > 0:
                found.append(ip+" -- no response")
            
            text, date=line = line.split(detec_tr)
            found.append(data+" --"+date.rstrip())
        i=i+1        
    return found, len(found)
    

def sw_scan(ssh, sw_found):    
    found=[]
    i=1
    for ip in sw_found:
        print "\rScanning %3d" % i, ('='*i)+('-'*(len(sw_found)-i)),   # status balken
        sys.stdout.flush()
        stdin, stdout, stderr = ssh.exec_command("ping -c 1 -w 1 "+ip)
        line=stdout.read()
        s=line.find(detec_ac)        
        if s > 0:
            found.append(ip+" active")
        i=i+1

    return found        
        
        
# ergebnis sichern
def write_file(sw_found, name, cnt_active, cnt_alive):        
    
    name=name+"_found.txt"    

    try:
        datei=open(name,"w")
    except Exception, e:
        sys.exit ("Cant write result file")

    datei.write(str(datetime.now()))
    datei.write("\nResult for "+name+" :")
    datei.write("\nAktive found "+str(cnt_active)+" alive found "+str(cnt_alive)+"\n\n")
    
    for line in sw_found:
        datei.write(str(line)+"\n")
        
    datei. close()
        
        
        
# -------------------------- main ------------------------------        

        
#detec=detec_sw
detec=detec_sw
cnt_alive = 0
cnt_active = 0
        
# arguments einlesen
try:
    myopts, args = getopt.getopt(sys.argv[1:],"hnpsev",["nwt","pex","scu","expl","vme"])
except getopt.GetoptError, err:
    print str(err)
    help_txt()   
    sys.exit(2)

for o, arg in myopts:
    if o in ("-h","--help"):
        help_txt()   
        sys.exit(2)
    elif o in ("-n","--nwt"):
        detec=detec_sw
    elif o in ("-p","--pex"):
        detec=detec_pex
    elif o in ("-s","--scu"):
        detec=detec_scu
    elif o in ("-e","--expl"):
        detec=detec_expl
    elif o in ("-v","--vme"):
        detec=detec_vme
    else: 
        detec=detec_sw
              
print "\nScan for "+detec
      
       
# login daten abfragen
username, pswd = logindata()

# host file copieren
copy_host(username, pswd)

# host file nach switchen durchsuchen
sw_found = extract(detec)

# ssh verbindung aufbauen
ssh=ssh_connect(username, pswd)

# switche scannen
swac_found=sw_scan(ssh, sw_found)
cnt_active=len(swac_found)
print"\nActive "+detec+" found: "+str(cnt_active)+"\n"

# keine switche -> datum ueberpruefen
if detec != detec_sw:
    swac_found, cnt_alive= alive(ssh, swac_found) 
    print"\nAlive "+detec+" found: "+str(cnt_alive)+"\n"

print "\n\n----"
print "Active/alive "+detec+" found :",cnt_active
print "----\n"

for line in swac_found:
    print line
   
# write file
write_file(swac_found, detec, cnt_active, cnt_alive)

#loesche host file
os.remove(datei_host)
    
print "\nfinish"
ssh.close()
