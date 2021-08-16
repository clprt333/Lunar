## Payloads
These are 'Payloads' that are executed in Memory using Reflective DLL Injection.

**output.png** is the file used to get output of these payloads. The payloads write output in this Image.
Lunar reads the output and sends back to the C2 server.

- ncshell - Netcat Basic Reverse shell.
- ReflectiveDll - Standard Reflective DLL, shows messagebox.
- ChromeDump - Dumps Chrome passwords to 'password.txt'.
- runasadmin - Used to execute programs as an adminstrator.
- msf - Executes metasploit C Shellcode via reflective dll. (Buggy)
- keylogger - A Standard GetAsyncKeyState Keylogger.
- miccapture - Records through the mic.
