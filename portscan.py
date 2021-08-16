import socket
import threading
from queue import Queue
import colorama
from colorama import Fore
colorama.init()
t = input("Input the target: ")
target = t
queue = Queue()
open_ports = []
print(Fore.GREEN + '''
@@@@@@@    @@@@@@   @@@@@@@   @@@@@@@      @@@@@@    @@@@@@@   @@@@@@   @@@  @@@  @@@  @@@  @@@@@@@@  @@@@@@@   
@@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@     @@@@@@@   @@@@@@@@  @@@@@@@@  @@@@ @@@  @@@@ @@@  @@@@@@@@  @@@@@@@@  
@@!  @@@  @@!  @@@  @@!  @@@    @@!       !@@       !@@       @@!  @@@  @@!@!@@@  @@!@!@@@  @@!       @@!  @@@  
!@!  @!@  !@!  @!@  !@!  @!@    !@!       !@!       !@!       !@!  @!@  !@!!@!@!  !@!!@!@!  !@!       !@!  @!@  
@!@@!@!   @!@  !@!  @!@!!@!     @!!       !!@@!!    !@!       @!@!@!@!  @!@ !!@!  @!@ !!@!  @!!!:!    @!@!!@!   
!!@!!!    !@!  !!!  !!@!@!      !!!        !!@!!!   !!!       !!!@!!!!  !@!  !!!  !@!  !!!  !!!!!:    !!@!@!    
!!:       !!:  !!!  !!: :!!     !!:            !:!  :!!       !!:  !!!  !!:  !!!  !!:  !!!  !!:       !!: :!!   
:!:       :!:  !:!  :!:  !:!    :!:           !:!   :!:       :!:  !:!  :!:  !:!  :!:  !:!  :!:       :!:  !:!  
 ::       ::::: ::  ::   :::     ::       :::: ::    ::: :::  ::   :::   ::   ::   ::   ::   :: ::::  ::   :::  
 :         : :  :    :   : :     :        :: : :     :: :: :   :   : :  ::    :   ::    :   : :: ::    :   : : 
''')
print(Fore.GREEN + "v2.0")
print(Fore.BLUE + "Made by Matthew Papadopoulos")


def portscan(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target, port))
        return True
    except Exception:
        return False


def fill_queue(port_list):
    for port in port_list:
        queue.put(port)


def worker():
    while not queue.empty():
        port = queue.get()
        if portscan(port):
            print(Fore.RED + "[!] HIDDEN SERVICE FOUND: " + Fore.WHITE + "{}".format(port))
            open_ports.append(port)
        elif portscan(port) is None:
            print(Fore.RED + "[?] NO SERVICE/S FOUND!")


port_list = range(1, 10248)
fill_queue(port_list)
thread_list = []
for t in range(500):
    thread = threading.Thread(target=worker)
    thread_list.append(thread)
for thread in thread_list:
    thread.start()
for thread in thread_list:
    thread.join()
print(Fore.GREEN + "[!] OPEN PORTS:", Fore.WHITE, open_ports, Fore.YELLOW + "@", Fore.RED, target)


