clear
if [[ $EUID -ne 0 ]]; then
   echo "[^] Run as root." 
   exit 1
fi
echo "Lunar C2 Installer"
apt-get install mingw-w64 
apt-get install python3-pip
pip3 install -r requirements.txt 
sleep 1
clear
echo "Done, you may now run Lunar."
