LUNAR BOTNET

Usage: sudo python3 main.py

Select 1 or 2. Make sure to check settings. (settings.ini and lunar.ini)
Do not click the executables within the directories, these are for the victim.
I AM NOT RESPONSIBLE FOR ANY DAMAGE YOU DO TO OTHERS OR YOURSELF YOU HAVE BEEN WARNED.

Contains 2 Modules

[1] For pre-exploitation
Lunar.ini
[Change host and Port to appropriate settings, ignore password field]
This a basic and effective RAT that can be implemented into other legitimate programs as a Trojan.
This RAT will acts as an entry point, and can upload and download files from a victim machine. This allows a user to drop the post exploitation payload.

[2] For post-exploitation
Settings.ini
[Change Host and Port to Appropriate Settings, Ignore Inject Process, (You can change this later on as this will be the default process the malware looks for when injecting DLL's into memory.
Lunar Royal Blue utilizes EternalBlue, an attack that utilizes an overflow between SMB requests that are not signed, and has since been patched.
This "Botnet" is a concept of the types of damages that could be done with an implementation of an EternalBlue attack within a Botnet.
This botnet also has the capabilities of dropping other types of malware into memory as a portable executable in the form of a DLL.
Many premade examples are within the payload section of the botnet.

Lunar_attack.rc
This file is the metasploit resource file that is produced for the botnet for the automated attacks within the botnet. Change the LHOST and the RHOST.

kernel/core.py 
You will find the autoattack code here. This generates the Lunar_attack.rc file, you can edit the various options within the code, or wait for a rcfile to be generated and edit the rcfile directly.

Both botnets have "Build" features, which will build the malware as long as you meet the pre-requisites of software.
This can be attained with chmod +x install.sh and python pip -r requirements.txt
Some modules you may miss:
geoip2
tgqm
impacket
plyer
names
colorama
stem
prompt_toolkit
PIL

(BUGS)
Royal Blue build fails on Kali Machines, this is possibly because of the pre-set path environments. However, I have not figured it out.
Build currently works on BackBox.

Lunar-Botnet. Created as an objective for an assignment at school.

You must edit the rc files and add the rhost, rport and other options when using auto attack.

You need GeoLite2-City.mmdb

You may also need to add a folder named "TARGETS" within the root directory.

pip install -r requirements.txt

Shoutout to quantumcored.

usage: https://youtu.be/nPPghaM_LjY

https://youtu.be/zLeZVPVyNL8
