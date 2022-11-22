
import re
import scapy.all as scapy
import requests
import argparse
import ctypes

HOSTS_PATH = "C:\Windows\System32\drivers\etc\hosts"
LAN_ADDRESS = "192.168.1.0/24"


# ARGUMENTS
def getArguments ():
    parser = argparse.ArgumentParser(
                        prog = 'hostUpdater',
                        epilog = 'Example: python.exe hostUpdater.py -a domain 1a:2b:3c:4d:5f:6g')

    parser.add_argument('-u', '--update', action='store_true', help='Update the addresses of the host file')
    parser.add_argument('-l', '--list', action='store_true', help='List hosts in the LAN and in the hosts file')
    parser.add_argument('-a', '--add', nargs=2, type=str, help='Add a new host to be auto updated when using -u parameter')

    return parser.parse_args()


def update ():
    # Update the hosts file

    hosts.open()
    netScanner.scan()
    print()
    for i in range(len(hosts.host_list)):
        for scanned_host in netScanner.host_list:
            if hosts.host_list[i]['mac'] == scanned_host['mac']:
                
                if (hosts.host_list[i]['ip'] != scanned_host['ip']):
                    hosts.host_list[i]['ip'] = scanned_host['ip']
                    print ('[+] IP of {} has been updated to {}'.format(hosts.host_list[i]['domain'], scanned_host['ip']))

    hosts.update()

    print ("[+] Hosts have been updated")


def list ():
    # Lists hosts from the hosts file and the network
    
    hosts.open()
    netScanner.scan()
    netScanner.downLoadOui()

    print('\nHost file\n-------')

    print ("{:<20} {:<20} {:<20}".format('IP','DOMAIN','MAC'))
    for host in hosts.host_list:
        print ("{:<20} {:<20} {:<20}".format(host['ip'], host['domain'], host['mac']))
    print()

    print('\nHost LAN\n--------')
    print ("{:<20} {:<20} {}".format('IP','MAC','OUI'))
    for host in netScanner.host_list:
        print ("{:<20} {:<20} {}".format(host['ip'], host['mac'], netScanner.organization(host['mac'][0:8])))
    print()


def add (hostToAdd):
    # Adds a new host to be auto updated

    hosts.open()
    hosts.host_list.append({"ip": "", "domain": hostToAdd[0], "mac": hostToAdd[1]})
    hosts.update()

    update() # run the update function to assign an ip to the new host

    print("\n[+] {} added successfully".format(hostToAdd[0]))



class NetScanner:

    oui_list = ""


    def __init__(self, ip):
        self.ip = ip
        self.host_list = []

    def downLoadOui(self):
        # This method serves to download a file with a list of OUIs, it is separated from the
        # rest of the code to optimize times and only download if it will be used

        try:
            with requests.get("https://standards-oui.ieee.org/", timeout=5) as r:
                self.oui_list = r.text.split("\n")
        except:
            self.oui_list = ""

    def organization(self, oui):
        oui = oui.replace(":","-")
        for line in self.oui_list:
            if re.search(oui, line, re.IGNORECASE):
                org = re.compile('\t+(.*)\r$')
                return org.findall(line)[0]

    def scan(self):
        arp_req_frame = scapy.ARP(pdst = self.ip)

        broadcast_ether_frame = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
        
        broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame

        answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout = 1, verbose = False)[0]
        result = []
        for i in range(0,len(answered_list)):
            client_dict = {"ip" : answered_list[i][1].psrc, "mac" : answered_list[i][1].hwsrc}
            result.append(client_dict)

        self.host_list = result
        

        

class Hosts:

    start = "# hostsUpdater START"
    end = "# hostsUpdater END"

    def __init__(self, path):
        self.path = path
        self.host_list = []
        self.text = ""


    def open (self):

        with open(self.path, "r") as file:
            self.text = file.read()
            file.close()

        regex = '{}(.*?){}'.format(self.start, self.end)
        hostsPart = re.search(regex, self.text, re.DOTALL) # DOTALL makes '.' match '\n'

        # If the hostsUpdater part was not found, creates it and relaunch the method
        if hostsPart == None:
            with open(self.path, "a") as file:
                file.write("\n"+self.start+"\n"+self.end)
                file.close()
            self.open()
        
        else:
        
            for line in hostsPart.group().split('\n'): # With group, we extract the string that has matched

                # line format ->   ip  domain  # mac

                info = line.split() 
                self.host_list.append({"ip": info[0], "domain": info[1], "mac": info[3]}) if (len(info) == 4) else None


    def update (self):
        # Writes the new hosts file with the new configuration

        hostsPart = self.start+'\n\n'
        for i in self.host_list:
            hostsPart += ("\t{}\t{}\t# {}\n".format(i["ip"], i["domain"], i["mac"]))
        hostsPart += '\n'+self.end

        regex = '{}(.*?){}'.format(self.start, self.end)

        with open(self.path, "w") as file:
            file.write(re.sub(regex, hostsPart , self.text, flags=re.DOTALL)) # Replaces the hostsUpdater part with the new hosts
            file.close


if __name__ == "__main__":

    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    if is_admin():
        # Code executed as admin

        hosts = Hosts(HOSTS_PATH)
        netScanner = NetScanner (LAN_ADDRESS)
        
        args = getArguments()

        if args.update:
            update()
        elif args.list:
            list()
        elif args.add:
            add(args.add)

    else:
        print("[-] Error: You should run the program as administrator")