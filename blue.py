#!/usr/bin/python3
from kernel.core import *
from kernel.banner import p_banner


def blue():
    clear_screen()
    print(p_banner())
    Console()


