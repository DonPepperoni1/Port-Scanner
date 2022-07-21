import platform
from getmac import get_mac_address as gma
import subprocess
import os
import re
import requests
import socket
from ipaddress import IPv4Network
import argparse
import sys



#Parser pour le choix des arguments 
parser = argparse.ArgumentParser(description='Welcome to our Scanner, you can use this tools with multiple arguments. But if you want to perform FullScan, please type : -ps')
parser.add_argument("-d", "--subdom", help="Scan subdomains of a domain name", action='store_true')
parser.add_argument("-p", "--ping", help="Scan numbers of ip and chosen range of ports", action='store_true')
parser.add_argument("-s", "--soc", help="Scan ports for Ip address", action='store_true')
parser.add_argument("-o", "--out", help="Output results in .txt file", action='store_true')
parser.add_argument("-ps", "--full", help="Ports Scan of awaken hosts", action='store_true')
args = parser.parse_args()

# !!! Vous avez besoin d'installer la librairie getmac avant de lancer ce script : "pip install getmac"

# Début du script
# Trouver les informations commune à chaque système :
se = platform.system()
hostname = socket.gethostname()
ip = socket.gethostbyname(hostname)
path = os.listdir('.')
print("Votre système d'exploitation est : ", se, "\nVotre adresse MAC est : ", gma(), "\nVotre adresse IP est : ", ip)

'''Création d'une fonction pour différencier la commande de récupération d'informations des interfaces
entre Windows et Linux/Mac (ifconfig/ipconfig)'''

def getinfo(se, path):
    if se == "Windows":
        ipconf = subprocess.check_output("ipconfig")

    elif se == "Darwin" or se == "Linux":
        ipconf = subprocess.check_output("ifconfig").decode("utf-8")

    else:
        print("Votre système n'est pas reconnu :/ !")
    # Création du fichier confIP.txt avec la variable ipconf qui différenciera le résultat en fonction du système d'exploitation.
    with open('confIP.txt', 'w+') as file:
        file.write(str(ipconf))

    # Récupération et affichage des adresses IP trouvées dans le fichier confIP.txt
    with open('confIP.txt', 'r') as f:
        pattern = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        print('\nVoici le(s) Ip trouvée(s) sur votre machine :')
        for line in f:
            final_ip = re.findall(pattern, line)
            if final_ip:
                for i in final_ip:
                    print(i)

    # Liste fichiers du dossier actuel :
    #print("\nVoici les fichiers et dossiers présents dans votre répertoire actuel :")
    #for i in path:
        #print(i)

getinfo(se, path)

#Remove outdated file
if os.path.exists("IpUp.txt"):
    os.remove("IpUp.txt")

# Function FullScan (Host up + port scanner)
def fullScan(addr, ports):
    try:
# Test si host UP
# Changement de la commande ping en fonction de l'OS détécté
        if se == "Windows":
            res = subprocess.call(['ping', '/n', '2', '/l', '1', '-i', '0.2', '/W', "550", str(addr)])
        elif se == "Darwin" or "Linux":  
            res = subprocess.call(['ping', '-c', '2', '-s', '1', '-i', '0.2', '-W', "550", str(addr)])
    except:
        None
# Si host up alors scan des ports
    if res == 0:
        print("#")
        print("ping to", addr, "OK")
        print("#")
        scan(addr, ports)
        if args.out:
            with open('IpUp.txt', 'a') as file:
                file.write(str(addr) + ' \n')    
    elif res == 2:
        print("no response from", addr)
    else:
        print("ping to", addr, "failed!")

#Fonction de test Ping
def pingIp(addr, ports):
    try:
# Changement de la commande ping en fonction de l'OS détécté
        if se == "Windows":
            res = subprocess.call(['ping', '/n', '2', '/l', '1', '-i', '0.2', '/W', "550", str(addr)])
        elif se == "Darwin" or "Linux":  
            res = subprocess.call(['ping', '-c', '2', '-s', '1', '-i', '0.2', '-W', "550", str(addr)])
    except:
        None
# Si host up 
    if res == 0:
        print("#")
        print("ping to", addr, " OK")
        print("#")
#Si argument -o alors écriture dans le fichier IpUp.txt
        if args.out:
            with open('IpUp.txt', 'a') as file:
                file.write(str(addr) + ' \n')    

    elif res == 2:
        print("no response from", addr)
    else:
        print("ping to", addr, "failed!")

#Fonction simple de scan de ports avec choix du nombre de ports
def scan(target, ports):
    print('\n' + ' Starting scan For ' + str(target))
    for port in range(1, ports):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect((target, port))
            print("[+] Port Opened " + str(port))
        except :
            pass
            

# si args = -ps
if args.full:
    print("Enter in Full Scan Mode :")
    #targets = ""
    #if targets:
    targets = input("[*] Enter Targets To Scan(split them by , or add CIDR like /24 after ipaddress): ")
    ports = int(input("[*] Enter How Many Ports You Want To Scan: "))
    #else:
    if '/' in targets:
        print("[+] Scanning Range Multiple Targets")
        net = IPv4Network(targets, False)
        print("Net =>", net.hosts())
        for addr in net.hosts():
            print("Addr => ", str(addr))
            fullScan(str(addr), ports)
    if ',' in targets:
        print("[+] Scanning Multiple Targets")
        for ip_addr in targets.split(','):
            fullScan(ip_addr.strip(' '), ports)
    else:
        fullScan(targets, ports)

# si args = -p
if args.ping:
    targets = input("[*] Enter Targets To Scan(split them by , or add CIDR like /24 after ipaddress): ")
    ports = 0
    if '/' in targets:
        print("[+] Scanning Range Multiple Targets")
        net = IPv4Network(targets, False)
        for addr in net:
            pingIp(addr, ports)
    if ',' in targets:
        print("[+] Scanning Multiple Targets")
        for ip_addr in targets.split(','):
            pingIp(ip_addr.strip(' '), ports)
    else:
        pingIp(targets, ports)
       
# si args = -s
if args.soc:
    #targets = ""
    #if targets:
    targets = input("[*] Enter Targets To Scan(split them by , or add CIDR like /24 after ipaddress): ")
    ports = int(input("[*] Enter How Many Ports You Want To Scan: "))
    #else:
    if '/' in targets:
        print("[+] Scanning Range Multiple Targets")
        net = IPv4Network(targets, False)
        print("Net =>", net.hosts())
        for addr in net:
            print("Addr => ", str(addr))
            scan(str(addr), ports)
    if ',' in targets:
        print("[+] Scanning Multiple Targets")
        for ip_addr in targets.split(','):
            scan(ip_addr.strip(' '), ports)
    else:
        scan(targets, ports)


# Domains_Scanner
if args.subdom:
#Si le fichier out.txt existe, on le supprime
    if os.path.exists("out.txt"):
        os.remove("out.txt")
    def domain_scanner(domain_name, sub_domnames):
        print('-----------Scanner Started-----------')
        print('----URL after scanning subdomains----')

# Cette boucle permet de requeter chaque sous domaines identifier dans la wordlist
        for subdomain in sub_domnames:
#variable permettant de requeter dynamiquement
            url = f"https://{subdomain}.{domain_name}"
            try:
                requests.get(url)
#Affichage de la requete
                print(f'[+] {url}')
#Si argument -o placé, écriture dans le fichier out.txt
                if args.out:
                    with open('out.txt', 'a') as export:
                        export.write(str(url) + ' \n')
#except si la requete est fausse
            except requests.ConnectionError:
                pass
        print('\n')
        print('----Scanning Finished----')
        print('-----Scanner Stopped-----')

#Input du domaine choisi
    if __name__ == '__main__':
        dom_name = input("Enter the Domain Name:")
        print('\n')

    with open('grosse_wordlist.txt', 'r') as file:
        name = file.read()
        # appel de spilitlines() qui stocke la liste des chaînes de caractères scindées
        sub_dom = name.splitlines()

    dom_scan = domain_scanner(dom_name, sub_dom)