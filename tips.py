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

act_firm="firm-mon"
act_netm="net-mon"
act_wrm ="wr-mon"
act_no="No Action"
act_all="over all"

sw_found = []
sw_active = []
all_found = []

# hilfe anzeigen
def help_txt():
    print "Timing IP Scanner (tips)"
    print "scan the host-file on the tsl001 for the wanted unit"
    print "testing it is online (ping) and make the desired action"
    print "arguments are :"
    print "-n  --nwt   scan all wr-switches"
    print "-p  --pex   scan all pexarias"
    print "-s  --scu   scan all scu's"
    print "-e  --expl  scan all exploder"  
    print "-v  --vme   scan all vme's"
    print "action:"
    print "-f --firm-mon"
    print "-t --net-mon"
    print "-w --wr-mon"
    print "-a --all"
 
 
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
    except Exception:
        sys.exit ("FAILURE !")    
    print "...success"


# tsloo1 verbindung aufbauen
def ssh_connect(uname, pswd):
    print "\nConnecting tsl001..."
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=server_adress, username=uname, password=pswd)
    except Exception:
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
    except Exception:
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
def wrmon(ssh, swac_found):
    found=[]
    i=1    
    cnt_err=0
    found.append("\n--- wr-mon --")
    for data in swac_found:
        print "\rwr-mon investigation in progress: %3d" % i, ('='*i)+('-'*(len(swac_found)-i)),   # status balken
        sys.stdout.flush()       
        ip, text = data.split(" ")        
        stdin, stdout, stderr = ssh.exec_command(PFAD_monitor+act_wrm+" udp/"+ip)        
        line=stdout.read()
        error=stderr.read()
            
        if error != "":
            found.append(data +" --ERROR:"+error.rstrip())
            cnt_err=cnt_err+1
        else :
            s=line.find(detec_al)
            if s > 0:
                found.append(ip+" -- no response")
            
            text, date, text_sy, sy_status=line = line.split(detec_tr)
            found.append(data+" --"+date.rstrip()+" --"+sy_status.rstrip())
        i=i+1        
    return found, (len(found)-cnt_err)
    
    
def netmon(ssh, swac_found):
    found=[]
    i=1
    cnt_err=0
    found.append("\n--- net-mon --")
    for data in swac_found:
        print "\rnet-mon investigation in progress: %3d" % i, ('='*i)+('-'*(len(swac_found)-i)),   # status balken
        sys.stdout.flush()
        ip, text = data.split(" ")  
        stdin, stdout, stderr = ssh.exec_command(PFAD_monitor+act_netm+" udp/"+ip) 
        line=stdout.read()
        error=stderr.read()
        if error != "":
            found.append(data +" --ERROR:"+error.rstrip())
            cnt_err=cnt_err+1        
        else:
            found.append("---")
            found.append(data+" :\n")
            found.append(line+"\n")
        i=i+1                   
    return found, (len(found)-cnt_err)     
    
    
def firmmon(ssh, swac_found):
    found=[]
    i=1
    index=1
    cnt_err=0
    found.append("\n--- firm-mon --")
    for data in swac_found:
        print "\rfirm-mon investigation in progress: %3d" % i, ('='*i)+('-'*(len(swac_found)-i)),   # status balken
        sys.stdout.flush()
        ip, text = data.split(" ")
        stdin, stdout, stderr = ssh.exec_command(PFAD_monitor+act_firm+" udp/"+ip)        
        line=stdout.read()
        error=stderr.read()
        if error != "":
            found.append(data +" --ERROR:"+error.rstrip())
            cnt_err=cnt_err+1        
        else:
            found.append("---")
            found.append(data+" :\n")  
            line=line.split("\n")
            while index < 8:
                try:
                    found.append(line[index])
                except:
                    found.pop(-1)
                    found.append("NO VAILID DATA")
                    index=8
                index=index+1
        i=i+1
        index=1
    return found, (len(found)-cnt_err)       
                 

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
def write_file(sw_found, name, action, cnt_active, cnt_all):        
    
    dname=name+"_found.txt"    

    try:
        datei=open(dname,"w")
    except Exception:
        sys.exit ("Cant write result file")

    datei.write(str(datetime.now()))
    datei.write("\nScan for "+name+" execute "+action)
    datei.write("\nAktive "+str(cnt_active)+" found from registered "+str(cnt_all)+" units\n\n")
    
    for line in sw_found:
        datei.write(str(line)+"\n")
        
    datei. close()
        
        
        
# -------------------------- main ------------------------------        

        
# default werte
detec=detec_sw
action=act_no
cnt_alive = 0
cnt_active = 0
        
# arguments einlesen
try:
    myopts, args = getopt.getopt(sys.argv[1:],"hnpsevftwa",["nwt","pex","scu","expl","vme","firm-mon","net-mon","wr-mon","all"])
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
    elif o in ("-f","--firm-mon"):
        action=act_firm
    elif o in ("-t","--net-mon"):
        action=act_netm
    elif o in ("-w","--wr-mon"):
        action=act_wrm
    elif o in ("-a", "--all"):
        action=act_all        
    else: 
        help_txt()
              
print "\nScan for "+detec+" execute "+action      
       
# login daten abfragen
username, pswd = logindata()

# host file copieren
copy_host(username, pswd)

# host file nach der gesuchten unit durchsuchen
sw_found = extract(detec)

# ssh verbindung aufbauen
ssh=ssh_connect(username, pswd)

# units scannen
ping_found=sw_scan(ssh, sw_found)
cnt_active=len(ping_found)

print"\nActive "+detec+" found: "+str(cnt_active)+"\n"


if action != act_no:
    if (action == act_firm) or (action == act_all):
        swac_found, cnt_alive= firmmon(ssh, ping_found)
        print"\n"
        all_found=all_found+swac_found        
        del swac_found[:]         
        
    if (action == act_netm) or (action == act_all):
        swac_found, cnt_alive= netmon(ssh, ping_found)
        print"\n"
        all_found=all_found+swac_found
        del swac_found[:]

    if (action == act_wrm) or (action == act_all): 
        swac_found, cnt_alive= wrmon(ssh, ping_found) 
        print"\n"
        all_found=all_found+swac_found
        del swac_found[:]
else:
    all_found=ping_found


print "\n\n----"
print "Result: execute "+action+" "+detec+" found :",cnt_active
print "----\n"

for line in all_found:
    print line
   
#write file
write_file(all_found, detec, action, cnt_active, len(sw_found))

#loesche host file
os.remove(datei_host)
    
print "\nfinish"
ssh.close()
