from colorama import Fore, Style
import colorama
import random

colorama.init()
red = Fore.RED
blue = Fore.BLUE
green = Fore.GREEN
yellow = Fore.YELLOW
pink = Fore.LIGHTMAGENTA_EX
lightblue = Fore.CYAN
purple = Fore.MAGENTA


def colors():
        return random.choice([blue, yellow, pink, green, red, purple, lightblue])


banner = colors() + r'''
          .__....._             _.....__,
           - ": o :';         ;': o :" -
            `. `-' .'.       .'. `-' .'
              `---'             `---'
                       LUNAR
    _...----...      ...   ...      ...----..._
 ''' + colors() + '''.-'__..-""'----    `.  `"`  .'    ----'""-..__`-.
'.-'   _.--"""'       `-._.-'       '"""--._   `-.`
'  .-"'                  :                  `"-.  `
 .'   `.              _.'"'._              .'   `
        `.       ,.-'"       "'-.,       .'
          `.                           .'
            `-._                   _.-'
                `"'--...___...--'"`                                        
''' + Style.RESET_ALL

banner_two = colors() + r"""
 o                     __...__     *               
              *   .--'    __.=-.             o
     |          ./     .-'     
    -O-        /      /   
     |        /    '"/               *
             |     (@)     
            |        \                         .
            |         \
 *          |       ___\                  |
             |  .   /  `                 -O-
              \  `~~\                     |
         o     \     \            *         
                `\    `-.__           .  
    .             `--._    `--'jgs
                       `---~~`                *
            *                   o
                                                        """ + Style.RESET_ALL

banner_three = colors() + r"""

▄▄▌  ▄• ▄▌ ▐ ▄  ▄▄▄· ▄▄▄  
██•  █▪██▌•█▌▐█▐█ ▀█ ▀▄ █·
██▪  █▌▐█▌▐█▐▐▌▄█▀▀█ ▐▀▀▄ 
▐█▌▐▌▐█▄█▌██▐█▌▐█ ▪▐▌▐█•█▌
.▀▀▀  ▀▀▀ ▀▀ █▪ ▀  ▀ .▀  ▀
""" + Style.RESET_ALL


banner_four = colors() + r"""

 ██▓     █    ██  ███▄    █  ▄▄▄       ██▀███  
▓██▒     ██  ▓██▒ ██ ▀█   █ ▒████▄    ▓██ ▒ ██▒
▒██░    ▓██  ▒██░▓██  ▀█ ██▒▒██  ▀█▄  ▓██ ░▄█ ▒
▒██░    ▓▓█  ░██░▓██▒  ▐▌██▒░██▄▄▄▄██ ▒██▀▀█▄  
░██████▒▒▒█████▓ ▒██░   ▓██░ ▓█   ▓██▒░██▓ ▒██▒
""" + colors() + """░ ▒░▓  ░░▒▓▒ ▒ ▒ ░ ▒░   ▒ ▒  ▒▒   ▓▒█░░ ▒▓ ░▒▓░
░ ░ ▒  ░░░▒░ ░ ░ ░ ░░   ░ ▒░  ▒   ▒▒ ░  ░▒ ░ ▒░
  ░ ░    ░░░ ░ ░    ░   ░ ░   ░   ▒     ░░   ░ 
    ░  ░   ░              ░       ░  ░   ░     
                                             

""" + Style.RESET_ALL

banner_five = colors() + r'''

    .o oOOOOOOOo                                            OOOo
    Ob.OOOOOOOo  OOOo.      oOOo.                      .adOOOOOOO
    OboO"""""""""""".OOo. .oOOOOOo.    OOOo.oOOOOOo.."""""""""'OO
    OOP.oOOOOOOOOOOO "POOOOOOOOOOOo.   `"OOOOOOOOOP,OOOOOOOOOOOB'
    `O'OOOO'     `OOOOo"OOOOOOOOOOO` .adOOOOOOOOO"oOOO'    `OOOOo
    .OOOO'            `OOOOOOOOOOOOOOOOOOOOOOOOOO'            `OO
    OOOOO                 '"OOOOOOOOOOOOOOOO"`                oOO
   oOOOOOba.                .adOOOOOOOOOOba               .adOOOOo.
  ''' + colors() + '''oOOOOOOOOOOOOOba.    .adOOOOOOOOOO@^OOOOOOOba.     .adOOOOOOOOOOOO
 OOOOOOOOOOOOOOOOO.OOOOOOOOOOOOOO"`  '"OOOOOOOOOOOOO.OOOOOOOOOOOOOO
 "OOOO"       "YOoOOOOMOIONODOO"`  .   '"OOROAOPOEOOOoOY"     "OOO"
    Y           'OOOOOOOOOOOOOO: .oOOo. :OOOOOOOOOOO?'         :`
    :            .oO%OOOOOOOOOOo.OOOOOO.oOOOOOOOOOOOO?         .
    .            oOOP"%OOOOOOOOoOOOOOOO?oOOOOO?OOOO"OOo
                 '%o  OOOO"%OOOO%"%OOOOO"OOOOOO"OOO':
                      `$"  `OOOO' `O"Y ' `OOOO'  o             .
    .                  .     OP"          : o     .
                              :
                              .
    ''' + colors() + '''The Devil is at his strongest when we are looking the other way,
    like a program running in the background silently. While we're busy doing
    other shit.        
''' + Style.RESET_ALL


def p_banner():
    """
    Generator that randomly picks a banner.
    """
    return random.choice([banner, banner_two, banner_three, banner_four, banner_five])

