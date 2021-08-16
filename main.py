from lunar import lunar
from blue import blue
import sys
from colorama import Fore, Style

print(
    Fore.MAGENTA +
    '''
██╗     ██╗   ██╗███╗   ██╗ █████╗ ██████╗      ██████╗  █████╗ ████████╗███████╗██╗    ██╗ █████╗ ██╗   ██╗
''' + Fore.CYAN + '''██║     ██║   ██║████╗  ██║██╔══██╗██╔══██╗    ██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝██║    ██║██╔══██╗╚██╗ ██╔╝
''' + Fore.MAGENTA + '''██║     ██║   ██║██╔██╗ ██║███████║██████╔╝    ██║  ███╗███████║   ██║   █████╗  ██║ █╗ ██║███████║ ╚████╔╝ 
''' + Fore.CYAN + '''██║     ██║   ██║██║╚██╗██║██╔══██║██╔══██╗    ██║   ██║██╔══██║   ██║   ██╔══╝  ██║███╗██║██╔══██║  ╚██╔╝  
''' + Fore.MAGENTA + '''███████╗╚██████╔╝██║ ╚████║██║  ██║██║  ██║    ╚██████╔╝██║  ██║   ██║   ███████╗╚███╔███╔╝██║  ██║   ██║   
''' + Fore.CYAN + '''╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝     ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝'''
)


def gateway():
    print(Style.BRIGHT + """
    """ + Fore.MAGENTA + """[1] Lunar 
    """ + Fore.CYAN + """[2] Lunar - Royal Blue (Make sure you have sudo privileges!)
    """)
    try:
        target = input("Select an Option: ")
        if target == "1":
            lunar()
        elif target == "2":
            blue()
        elif target == "exit":
            sys.exit()
    except KeyboardInterrupt:
        print("\nCtrl + C Input Received. Exiting...")
        pass

gateway()
