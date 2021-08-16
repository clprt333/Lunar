import geoip2.database
import socket
database_path = "GeoLite2-City.mmdb"


def scan_ip(ip_address):
    try:
        database = geoip2.database.Reader(database_path)
        ip_info = database.city(ip_address)
        iso_code = ip_info.country.iso_code
        country = ip_info.country.name
        postal_code = ip_info.postal.code
        region = ip_info.subdivisions.most_specific.name
        city = ip_info.city.name
    # location = str(ip_info.location.latitude) + " " + str(ip_info.location.longitude)
        location = "https://www.google.com/maps?q="+str(ip_info.location.latitude)+","+str(ip_info.location.longitude)
        print("[+] IP               : " + str(ip_address))
        print(" |_ ISO Code          : " + str(iso_code))
        print(" |_ Country           : " + str(country))
        print(" |_ Postal Code       : "+str(postal_code))
        print(" |_ Region            : " + str(region))
        print(" |_ City              : " + str(city))
        print(" |_ Location          : " + str(location))
    except Exception as ERROR:
        print("[SCANNER ERROR] : {error}".format(error=ERROR))
        print("[+] IP               : " + str(ip_address))
        print(" |_ Do further scanning with nmap and / or Blacklist.")
