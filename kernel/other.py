import os
from colorama import Style, Fore
import colorama
from PIL import Image
from plyer import notification
import geoip2.database
colorama.init()

banner = Fore.RED + Style.BRIGHT + """
                                        
 ____________________________________                 ______________
|------|------|     __   __   __     |     ___________     |           () |
| 64X4 | 64X4 | || |  | |  | |  |    |    |           |    |           ___|
|------|------| || |  | |  | |  |    |____|           |____|         || D |
| 64X4 | 64X4 | || |__| |__| |__|                 ________________  ||| I |
|------|------|  |  ________   ______   ______   | ADV476KN50     | ||| P |
| 64X4 | 64X4 |    |TRIDENT | |______| |______|  | 1-54BV  8940   | ||| S |
|------|------| || |TVGA    | |______| |______|  |________________| |||___|
| 64X4 | 64X4 | || |8800CS  |          ________________                ___|
|------|------| || |11380029|    LOW->|  /\ SUPER VGA  | _________    |   |
| 64X4 | 64X4 |     --------    BIOS  | \/         (1) ||_________|   | 1 |
|------|------| ||  ______  J  ______ |________________| _________    | 5 |
| 64X4 | 64X4 | || |______| 2 |______| ________________ |_________|   |___|
|------|------| ||  ________   ______ |  /\ SUPER VGA  |               ___|
| 64X4 | 64X4 |    |________| |______|| \/         (2) |   _________  |   |
|------|------| ()              HIGH->|________________|  |_________| | 9 |
 | 64X4 | 64X4 |     ________   _________   _____________   _________  |   |
 |______|______|__  |________| |_________| |_____________| |_________| |___|
                 |               __    TVGA-1623D                    _ () |
                 |LLLLLLLLLLLLLL|  |LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL| |___|
                                                                          |
                                                                          |
                     
                        """ + Fore.YELLOW + """Defying All Odds""" + Fore.GREEN + """
                        [Version : 1.0.0]""" + Style.RESET_ALL

proc_monitor = Style.BRIGHT + Fore.BLUE + r"""
 ▄▄▄·▄▄▄         ▄▄· ▄▄▄ ..▄▄ · .▄▄ ·     • ▌ ▄ ·.        ▐ ▄ ▪  ▄▄▄▄▄      ▄▄▄  
▐█ ▄█▀▄ █·▪     ▐█ ▌▪▀▄.▀·▐█ ▀. ▐█ ▀.     ·██ ▐███▪▪     •█▌▐███ •██  ▪     ▀▄ █·
 ██▀·▐▀▀▄  ▄█▀▄ ██ ▄▄▐▀▀▪▄▄▀▀▀█▄▄▀▀▀█▄    ▐█ ▌▐▌▐█· ▄█▀▄ ▐█▐▐▌▐█· ▐█.▪ ▄█▀▄ ▐▀▀▄ 
▐█▪·•▐█•█▌▐█▌.▐▌▐███▌▐█▄▄▌▐█▄▪▐█▐█▄▪▐█    ██ ██▌▐█▌▐█▌.▐▌██▐█▌▐█▌ ▐█▌·▐█▌.▐▌▐█•█▌
.▀   .▀  ▀ ▀█▄▀▪·▀▀▀  ▀▀▀  ▀▀▀▀  ▀▀▀▀     ▀▀  █▪▀▀▀ ▀█▄▀▪▀▀ █▪▀▀▀ ▀▀▀  ▀█▄▀▪.▀  ▀

            Process Monitor for Host : {ip}
"""

lunarhelp = r"""

HELP
----------------------------------

-> Session Core Commands :
----------------------------------
-. {ses} help - Print this help message.
-. {ses} show options - View Lunar Attack Options.
-. {ses} show targets - View Scanned Targets.
-. {ses} set target < target > - Set a Target to Attack.*
-. {ses} set attackport < port > - Set Target Port to Attack.*
-. {ses} set exploitport < port > - Set Port to send Exploits on (Default is random).*
-. {ses} show info - Show information on the Selected Target.
-. {ses} clear_hosts - Clear All Hosts.
-. {ses} clear_ports - Clear all Ports.
-. {ses} run - Start Pivoting Tunnel.
-. {ses} run autoblue - Automatically runs Eternal Blue on the set Target. Designed for Server 2016
-. {ses} run autoblue2 - Automaticlaly runs Eternal Blue on the set Target. Designed for Server Windows 10
-. {ses} run autoscanner - Scans for named pipes.
-. help - Print this help message.


-> Session Commands :
----------------------------------
-. {ses} ls - List files in current directory.
-. {ses} cd < dir > - Go in another directory.
-. {ses} delete - delete file.
-. {ses} download - Download file.
-. {ses} upload - Upload file.
-. {ses} osinfo - systeminfo output.
-. {ses} shell - Reverse shell. (With command prompt)
-. {ses} clientinfo - View basic information of Lunar.
-. {ses} port_scan - Scan for open ports on a Host.
-. {ses} network_scan - Scan the network.
-. {ses} tasklist - View Running Processes.
-. {ses} taskkill - Kill Running Process.
-. {ses} host_sweep - Get all hostnames of scanned targets or specific IP (use -h to specify ip). (Buggy)
-. {ses} dllinject - Reflective DLL Injection. Load your own Reflective DLL.
-. {ses} windefender_exclude - Add Windows Defender Exclusions.
    - To upload other malware, add Exclusions and upload malware to that directory, Not recommended uploading to disk. Load Reflective Dll instead.
-. {ses} screenshot - Take Screenshot.
-. {ses} psinfo - Get process information.
-. {ses} isadmin - Check if LUNAR has administrator rights.
-. {ses} geolocate - Get Geolocation.

CMD POST Exploitation Commands :
----------------------------------
-. {cmd} netuser - List users.
-. {cmd} systeminfo - View full System Information.
-. {cmd} driverquery - View all Drivers.
-. {cmd} tasklist - Get list of running processes.
-. {cmd} drives - Get Available Drive Letters.
-. {cmd} set - Get all environment variables. 
-. {cmd} qwinsta - Displays information about sessions on a Remote Desktop Session Host server.
-. {cmd} netshall - Acronym for 'netsh wlan show profiles'.
-. {cmd} rdp_enable - Enable Remote Desktop.
-. {cmd} rdp_disable - Disable Remote Desktop.
-. {cmd} firewall_off - Disable Firewall.
-. {cmd} firewall_on - Enable firewall.
-. {cmd} portfwd - Forward a PORT on the Remote PC.
-. {cmd} portfwd_reset - Reset all forwarded Ports.
-. {cmd} samdump - Dump SAM database.

DPS : 
----------------------------------
-. {dps} rshell - Netcat Reverse Shell.
-. {dps} dropmsf - In Memory Meterpreter.
-. {dps} runasadmin - Run an application as Administrator.
-. {dps} chromedump - Dump Google Chrome Passwords.
-. {dps} keylog_start - Start Capturing keystrokes.
-. {dps} keylog_stop - Stop Capturing keystrokes, And dump keylogs.
-. {dps} capturemic - Record microphone.

""".format(dps=Style.BRIGHT + Fore.GREEN + "(DPS)" + Style.RESET_ALL,
           cmd=Style.BRIGHT + Fore.MAGENTA + "(CMD)" + Style.RESET_ALL,
           ses=Style.BRIGHT + Fore.BLUE + "(SES)" + Style.RESET_ALL)


def clear_screen():
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")


def uniquify(path):
    filename, extension = os.path.splitext(path)
    counter = 1

    while os.path.exists(path):
        path = filename + " (" + str(counter) + ")" + extension
        counter += 1

    return path


def xor(data, key):
    output = []
    for i in range(len(data)):
        xor_num = ord(data[i]) ^ ord(key[i % len(key)])
        output.append(chr(xor_num))
    return ''.join(output)


def save_and_show_image(image):
    try:
        im = Image.open(image)
        im.save(image, "PNG")
        im.show()
    except Exception as e:
        print("[!] Error converting bmp to png : " + str(e))


def print_txt_file(filename):
    try:
        with open(filename, "r") as inn:
            data = inn.read()
            print(data)
    except Exception as e:
        print("[X] Error : " + str(e))


def notify(title, message):
    notification.notify(
        title,
        message
    )


def geo_locate(ip):
    database_path = "GeoLite2-City.mmdb"
    database = geoip2.database.Reader(database_path)
    ip_info = database.city(ip)
    iso_code = ip_info.country.iso_code
    country = ip_info.country.name
    postal_code = ip_info.postal.code
    region = ip_info.subdivisions.most_specific.name
    city = ip_info.city.name
    # location = str(ip_info.location.latitude) + " " + str(ip_info.location.longitude)
    location = "https://www.google.com/maps?q=" + str(ip_info.location.latitude) + "," + str(ip_info.location.longitude)
    print(
        """
        Geolocation 
        ----------------
        ISO Code : {iso_code}
        Country : {country}
        Postal Code : {postal_code}
        Region : {region}
        City : {city}
        Location : {loc}
        """.format(iso_code=iso_code,
                   country=country,
                   postal_code=postal_code,
                   region=region,
                   city=city,
                   loc=location)
    )
