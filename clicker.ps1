# script : clicker.ps1
# v : 9.0 (Hook mouse LLMHF_INJECTED)

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Le script nécessite les droits administrateur. Tentative de relancement..."
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoExit", "-File", """$PSCommandPath"""
    } catch {
        Write-Error "Échec du relancement en tant qu'administrateur. Veuillez lancer le script manuellement avec les droits admin."
        Read-Host "Appuyez sur Entrée pour quitter."
    }
    exit
}

try {
    Add-Type -TypeDefinition @"
    using System;
    using System.Diagnostics;
    using System.Runtime.InteropServices;
    using System.Windows.Forms;
    using System.Text;

    public static class Win32 {
        [DllImport("user32.dll")]
        public static extern short GetAsyncKeyState(int vKey);
    
        [DllImport("user32.dll")]
        public static extern void mouse_event(uint dwFlags, uint dx, uint dy, uint dwData, int dwExtraInfo);
        public const uint MOUSEEVENTF_LEFTDOWN = 0x02;
        public const uint MOUSEEVENTF_LEFTUP = 0x04;

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr SetWindowsHookEx(int idHook, IntPtr lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);
        
        public const int WH_KEYBOARD_LL = 13;
        public const int WH_MOUSE_LL = 14;
        public const int WM_KEYDOWN = 0x0100;
        public const int WM_LBUTTONDOWN = 0x0201;
        public const int WM_LBUTTONUP = 0x0202;
        public const uint LLMHF_INJECTED = 0x00000001;

        [StructLayout(LayoutKind.Sequential)]
        public struct POINT {
            public int x;
            public int y;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MSLLHOOKSTRUCT {
            public POINT pt;
            public uint mouseData;
            public uint flags;
            public uint time;
            public IntPtr dwExtraInfo;
        }

        // méthode az
        [DllImport("user32.dll")]
        public static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
        [DllImport("user32.dll", CharSet=CharSet.Auto)]
        public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
    }

    public static class KeyboardHook {
        private static IntPtr _hookID = IntPtr.Zero;
        private static Action<int> _callback;
        private static KeyboardProc _proc;

        public delegate IntPtr KeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        public static void Start(Action<int> callback) {
            _callback = callback;
            _proc = HookCallback;
            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule)
            {
                _hookID = Win32.SetWindowsHookEx(Win32.WH_KEYBOARD_LL, Marshal.GetFunctionPointerForDelegate(_proc), Win32.GetModuleHandle(curModule.ModuleName), 0);
            }
            Application.Run();
        }

        public static void Stop() {
            if(_hookID != IntPtr.Zero) {
                Win32.UnhookWindowsHookEx(_hookID);
                _hookID = IntPtr.Zero;
            }
            Application.ExitThread();
        }

        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam) {
            if (nCode >= 0 && wParam == (IntPtr)Win32.WM_KEYDOWN) {
                int vkCode = Marshal.ReadInt32(lParam);
                _callback(vkCode);
            }
            return Win32.CallNextHookEx(_hookID, nCode, wParam, lParam);
        }
    }

    public static class MouseHook {
        private static IntPtr _hookID = IntPtr.Zero;
        private static Action<bool> _callback;
        private static MouseProc _proc;

        public delegate IntPtr MouseProc(int nCode, IntPtr wParam, IntPtr lParam);

        public static void Start(Action<bool> callback) {
            _callback = callback;
            _proc = HookCallback;
            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule)
            {
                _hookID = Win32.SetWindowsHookEx(Win32.WH_MOUSE_LL, Marshal.GetFunctionPointerForDelegate(_proc), Win32.GetModuleHandle(curModule.ModuleName), 0);
            }
            Application.Run();
        }

        public static void Stop() {
            if(_hookID != IntPtr.Zero) {
                Win32.UnhookWindowsHookEx(_hookID);
                _hookID = IntPtr.Zero;
            }
            Application.ExitThread();
        }

        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam) {
            if (nCode >= 0) {
                if (wParam == (IntPtr)Win32.WM_LBUTTONDOWN) {
                    Win32.MSLLHOOKSTRUCT hookStruct = (Win32.MSLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(Win32.MSLLHOOKSTRUCT));
                    bool isInjected = (hookStruct.flags & Win32.LLMHF_INJECTED) != 0;
                    
                    // méthode clic dissociatif
                    if (!isInjected) {
                        _callback(true);
                    }
                }
                else if (wParam == (IntPtr)Win32.WM_LBUTTONUP) {
                    Win32.MSLLHOOKSTRUCT hookStruct = (Win32.MSLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(Win32.MSLLHOOKSTRUCT));
                    bool isInjected = (hookStruct.flags & Win32.LLMHF_INJECTED) != 0;
                    
                    if (!isInjected) {
                        _callback(false);
                    }
                }
            }
            return Win32.CallNextHookEx(_hookID, nCode, wParam, lParam);
        }
    }
"@ -ReferencedAssemblies "System.Windows.Forms"
} catch {
    Write-Error "error chargement composants C# pour les API Windows. error: $($_.Exception.Message)"
    exit
}

$syncHash = [hashtable]::Synchronized(@{
    Enabled = $false
    IsMousePressed = $false
    ActivationKey = 0x2E
    IsPowerShellActive = $false
    MinCPS = 12.7
    MaxCPS = 13.2
    MinClickDelayMs = 50
    MaxClickDelayMs = 83
    MenuState = 0
    InputBuffer = ""
    WaitingForInput = $false
    CPSStep = 1
})

$configFile = Join-Path $env:LOCALAPPDATA "PowerShell_Configuration_Settings_UserPreferences_Data_Storage_File_2025_Extended_Version_Configchakib.json"

function Get-KeyName {
    param($keyCode)
    $keyNames = @{
        0x41="A"; 0x42="B"; 0x43="C"; 0x44="D"; 0x45="E"; 0x46="F"; 0x47="G"; 0x48="H"; 0x49="I"; 0x4A="J"
        0x4B="K"; 0x4C="L"; 0x4D="M"; 0x4E="N"; 0x4F="O"; 0x50="P"; 0x51="Q"; 0x52="R"; 0x53="S"; 0x54="T"
        0x55="U"; 0x56="V"; 0x57="W"; 0x58="X"; 0x59="Y"; 0x5A="Z"
        0x30="0"; 0x31="1"; 0x32="2"; 0x33="3"; 0x34="4"; 0x35="5"; 0x36="6"; 0x37="7"; 0x38="8"; 0x39="9"
        0x70="F1"; 0x71="F2"; 0x72="F3"; 0x73="F4"; 0x74="F5"; 0x75="F6"
        0x76="F7"; 0x77="F8"; 0x78="F9"; 0x79="F10"; 0x7A="F11"; 0x7B="F12"
        0x20="Espace"; 0x0D="Entrée"; 0x09="Tab"; 0x1B="Échap"; 0x08="Backspace"; 0x2E="Delete"
        0x13="Pause"; 0x91="ScrollLock"; 0x2D="Insert"; 0x24="Home"; 0x23="End"; 0x21="PageUp"; 0x22="PageDown"
        0x05="Bouton3"; 0x06="Bouton4"; 0x04="Bouton5"
    }
    if ($keyNames.ContainsKey($keyCode)) { return $keyNames[$keyCode] } else { return "0x$($keyCode.ToString('X2'))" }
}

function Show-BaseInterface {
    Clear-Host
    $banner = @'
 ▄████▄   ██▓ ▄▄▄      
▒██▀ ▀█  ▓██▒▒████▄    
▒▓█    ▄ ▒██▒▒██  ▀█▄  
▒▓▓▄ ▄██▒░██░░██▄▄▄▄██ 
▒ ▓███▀ ░░██░ ▓█   ▓██▒
░ ░▒ ▒  ░░▓   ▒▒   ▓▒█░
  ░  ▒    ▒ ░  ▒   ▒▒ ░ 
░         ▒ ░  ░   ▒   
░ ░       ░        ░  ░  powershellClicker v0.33 by cia
░                      
'@
    Write-Host $banner -ForegroundColor Cyan

    Write-Host "--------------------------------------" -ForegroundColor DarkGray
    $currentKey = Get-KeyName $syncHash.ActivationKey
    Write-Host "    enabled/dislabed key : $currentKey" -ForegroundColor Yellow
    Write-Host "    CPS : $($syncHash.MinCPS) - $($syncHash.MaxCPS)" -ForegroundColor Yellow
    Write-Host "    press TAB to change the value (menu)" -ForegroundColor Yellow
    Write-Host "    config pactify : 12.7 13.2 à tester" -ForegroundColor Yellow
    Write-Host "--------------------------------------" -ForegroundColor DarkGray
}

function Save-Config {
    $config = @{
      ActivationKey = $syncHash.ActivationKey
      MinCPS = $syncHash.MinCPS
      MaxCPS = $syncHash.MaxCPS
      MinClickDelayMs = $syncHash.MinClickDelayMs
      MaxClickDelayMs = $syncHash.MaxClickDelayMs
    }
    $config | ConvertTo-Json | Out-File -FilePath $configFile -Encoding UTF8
}

function Load-Config {
    if (Test-Path $configFile) {
        try {
            $config = Get-Content -Path $configFile -Raw | ConvertFrom-Json
            $syncHash.ActivationKey = $config.ActivationKey
            $syncHash.MinCPS = $config.MinCPS
            $syncHash.MaxCPS = $config.MaxCPS
            $syncHash.MinClickDelayMs = $config.MinClickDelayMs
            $syncHash.MaxClickDelayMs = $config.MaxClickDelayMs
            Write-Host "cfg loaded from $configFile" -ForegroundColor Green
        } catch {
            Write-Host "Error cfg" -ForegroundColor Yellow
        }
    } else {
        Write-Host "0cfg" -ForegroundColor Yellow
    }
}

Load-Config

$null = ($runspace = [runspacefactory]::CreateRunspace())
$null = $runspace.Open()
$null = $runspace.SessionStateProxy.SetVariable("syncHash", $syncHash)

$null = ($powershell = [powershell]::Create())
$null = $powershell.Runspace = $runspace
$null = $powershell.AddScript({
    $callback = {
        param($vkCode)
        if ($vkCode -eq $syncHash.ActivationKey) {
            $syncHash.Enabled = -not $syncHash.Enabled
            if ($syncHash.Enabled) {
                [console]::beep(800, 150) 
            } else {
                [console]::beep(400, 150) 
            }
        }
    }
    $null = Register-ObjectEvent -InputObject ([System.AppDomain]::CurrentDomain) -EventName "ProcessExit" -Action { 
        [KeyboardHook]::Stop() 
    }
    [KeyboardHook]::Start($callback)
})
do { $handle = $powershell.BeginInvoke() } while ($false)

$null = ($mouseRunspace = [runspacefactory]::CreateRunspace())
$null = $mouseRunspace.Open()
$null = $mouseRunspace.SessionStateProxy.SetVariable("syncHash", $syncHash)

$null = ($mousePowershell = [powershell]::Create())
$null = $mousePowershell.Runspace = $mouseRunspace
$null = $mousePowershell.AddScript({
    $mouseCallback = {
        param($isPressed)
        $syncHash.IsMousePressed = $isPressed
    }
    $null = Register-ObjectEvent -InputObject ([System.AppDomain]::CurrentDomain) -EventName "ProcessExit" -Action { 
        [MouseHook]::Stop() 
    }
    [MouseHook]::Start($mouseCallback)
})
do { $mouseHandle = $mousePowershell.BeginInvoke() } while ($false)

$global:AzLauncherActive = $false
$timer = New-Object System.Timers.Timer 100
$timer.AutoReset = $true
$null = Register-ObjectEvent -InputObject $timer -EventName Elapsed -Action {
    try {
        $hwnd = [Win32]::GetForegroundWindow()
        if ($hwnd -eq [IntPtr]::Zero) { 
            $global:AzLauncherActive = $false
            $syncHash.IsPowerShellActive = $false
            return 
        }
        [uint32]$pid = 0
        [Win32]::GetWindowThreadProcessId($hwnd, [ref]$pid) | Out-Null
        if ($pid -eq 0) { 
            $global:AzLauncherActive = $false
            $syncHash.IsPowerShellActive = $false
            return 
        }
        $proc = [System.Diagnostics.Process]::GetProcessById($pid)
        $name = $proc.ProcessName.ToLower()
        $sb = New-Object System.Text.StringBuilder 256
        [Win32]::GetWindowText($hwnd, $sb, $sb.Capacity) | Out-Null
        $title = $sb.ToString().ToLower()
        $global:AzLauncherActive = ($name -match 'azlauncher|minecraft|java') -or ($title -match 'azlauncher|minecraft|java')
        $syncHash.IsPowerShellActive = ($name -match 'powershell|cmd|conhost|clicker') -or ($title -match 'powershell|cmd|clicker')
    } catch {
        $global:AzLauncherActive = $false
        $syncHash.IsPowerShellActive = $false
    }
}
$timer.Start()

$lastClickTime = (Get-Date).AddYears(-1)

Show-BaseInterface

try {
    while ($true) {
        if ($syncHash.IsPowerShellActive) {
            if ([Win32]::GetAsyncKeyState(0x09) -lt 0 -and $syncHash.MenuState -eq 0 -and -not $syncHash.WaitingForInput) {
                $syncHash.MenuState = 1
                Write-Host "`n=== MENU ===" -ForegroundColor Cyan
                Write-Host "1 - Change CPS" -ForegroundColor Yellow
                Write-Host "2 - Change Bind" -ForegroundColor Yellow
                Write-Host "0 - Close menu" -ForegroundColor Yellow
                Start-Sleep -Milliseconds 200
            } elseif ($syncHash.MenuState -eq 1 -and -not $syncHash.WaitingForInput) {
                if ([Win32]::GetAsyncKeyState(0x31) -lt 0) {
                    $syncHash.MenuState = 2
                    $syncHash.WaitingForInput = $true
                    $syncHash.InputBuffer = ""
                    Write-Host "`n=== CPS MENU ===" -ForegroundColor Cyan
                    Write-Host "Enter minimum CPS (5-50) then press Enter:" -ForegroundColor Yellow
                    Start-Sleep -Milliseconds 200
                } elseif ([Win32]::GetAsyncKeyState(0x32) -lt 0) {
                    $syncHash.MenuState = 3
                    Write-Host "`n=== BINDS MENU ===" -ForegroundColor Cyan
                    Write-Host "Press the desired key or mouse button:" -ForegroundColor Yellow
                    Start-Sleep -Milliseconds 200
                } elseif ([Win32]::GetAsyncKeyState(0x30) -lt 0) {
                    $syncHash.MenuState = 0
                    Write-Host "Menu closed" -ForegroundColor Green
                    Start-Sleep -Milliseconds 200
                }
            } elseif ($syncHash.MenuState -eq 2 -and $syncHash.WaitingForInput) {
                if ([Win32]::GetAsyncKeyState(0x0D) -lt 0) {
                    if ($syncHash.InputBuffer -ne "") {
                        if ($syncHash.CPSStep -eq 1) {
                            $cpsMin = [double]$syncHash.InputBuffer
                            if ($cpsMin -ge 5 -and $cpsMin -le 50) {
                                Write-Host "CPS min: $cpsMin" -ForegroundColor Green
                                $syncHash.MinCPS = $cpsMin
                                $syncHash.MinClickDelayMs = [math]::Round(1000 / $cpsMin)
                                $syncHash.InputBuffer = ""
                                $syncHash.CPSStep = 2
                                Write-Host "max cps (5-50cps) then press Enter:" -ForegroundColor Yellow
                            } else {
                                Write-Host "invalid value (5-50cps) try again" -ForegroundColor Red
                                $syncHash.InputBuffer = ""
                            }
                        } elseif ($syncHash.CPSStep -eq 2) {
                            $cpsMax = [double]$syncHash.InputBuffer
                            if ($cpsMax -ge 5 -and $cpsMax -le 50 -and $cpsMax -gt $syncHash.MinCPS) {
                                Write-Host "CPS max: $cpsMax" -ForegroundColor Green
                                $syncHash.MaxCPS = $cpsMax
                                $syncHash.MinClickDelayMs = [math]::Round(1000 / $cpsMax)
                                $syncHash.MaxClickDelayMs = [math]::Round(1000 / $syncHash.MinCPS)
                                Write-Host "CPS set : $($syncHash.MinCPS) - $($syncHash.MaxCPS)" -ForegroundColor Green
                                Write-Host "delays set : $($syncHash.MinClickDelayMs) - $($syncHash.MaxClickDelayMs) ms" -ForegroundColor Cyan
                                Start-Sleep -Milliseconds 1500
                                Save-Config
                                Show-BaseInterface
                                $syncHash.MenuState = 0
                                $syncHash.WaitingForInput = $false
                                $syncHash.CPSStep = 1
                            } else {
                                Write-Host "invalid value (must be > $($syncHash.MinCPS) and <= 50). Try again:" -ForegroundColor Red
                                $syncHash.InputBuffer = ""
                            }
                        }
                    }
                    Start-Sleep -Milliseconds 200
                } elseif ([Win32]::GetAsyncKeyState(0x08) -lt 0) {
                    if ($syncHash.InputBuffer.Length -gt 0) {
                        $syncHash.InputBuffer = $syncHash.InputBuffer.Substring(0, $syncHash.InputBuffer.Length - 1)
                        Write-Host "`b `b" -NoNewline
                    }
                    Start-Sleep -Milliseconds 100
                } else {
                    for ($i = 0x30; $i -le 0x39; $i++) {
                        if ([Win32]::GetAsyncKeyState($i) -lt 0) {
                            $char = [char]$i
                            $syncHash.InputBuffer += $char
                            Write-Host $char -NoNewline
                            Start-Sleep -Milliseconds 100
                            break
                        }
                    }
                    if ([Win32]::GetAsyncKeyState(0xBE) -lt 0) {
                        $syncHash.InputBuffer += "."
                        Write-Host "." -NoNewline
                        Start-Sleep -Milliseconds 100
                    }
                }
            } elseif ($syncHash.MenuState -eq 3) {
                $allKeys = @()
                
                for ($i = 0x41; $i -le 0x5A; $i++) { $allKeys += $i }
                for ($i = 0x30; $i -le 0x39; $i++) { $allKeys += $i }
                for ($i = 0x70; $i -le 0x7B; $i++) { $allKeys += $i }
                
                $specialKeys = @(0x20, 0x0D, 0x09, 0x1B, 0x08, 0x2E, 0x13, 0x91, 0x2D, 0x24, 0x23, 0x21, 0x22, 0x05, 0x06, 0x04)
                $allKeys += $specialKeys
                
                foreach ($key in $allKeys) {
                    if ([Win32]::GetAsyncKeyState($key) -lt 0) {
                        $syncHash.ActivationKey = $key
                        $keyName = Get-KeyName $key
                        Write-Host "bind set to: $keyName" -ForegroundColor Green
                        Start-Sleep -Milliseconds 1500
                        Save-Config
                        Show-BaseInterface
                        $syncHash.MenuState = 0
                        Start-Sleep -Milliseconds 200
                        break
                    }
                }
                if ([Win32]::GetAsyncKeyState(0x30) -lt 0) {
                    $syncHash.MenuState = 0
                    Write-Host "menu closed" -ForegroundColor Green
                    Start-Sleep -Milliseconds 200
                }
            }
        }
        
        if ($syncHash.Enabled -and $syncHash.IsMousePressed -and $global:AzLauncherActive) {
            $now = Get-Date
            $elapsed = ($now - $lastClickTime).TotalMilliseconds
            
            $randomCPS = Get-Random -Minimum $syncHash.MinCPS -Maximum $syncHash.MaxCPS
            $randomDelay = [math]::Round(1000 / $randomCPS)
            
            if ($randomDelay -gt 0 -and $elapsed -ge $randomDelay) {
                try {
                    [Win32]::mouse_event([Win32]::MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
                    Start-Sleep -Milliseconds (Get-Random -Minimum 10 -Maximum 21)
                    [Win32]::mouse_event([Win32]::MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
                    $lastClickTime = $now
                } catch {
                    Write-Host "error during click: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
        Start-Sleep -Milliseconds 1
    }
}
finally {
    Write-Host "`nclean & close ..."
    if ($runspace.RunspaceStateInfo.State -eq 'Opened') {
        $stopper = [powershell]::Create()
        $stopper.Runspace = $runspace
        $stopper.AddScript({ [KeyboardHook]::Stop() }) | Out-Null
        $stopper.Invoke()
        $handle.AsyncWaitHandle.WaitOne(500)
        $runspace.Close()
        $runspace.Dispose()
    }
    
    if ($mouseRunspace.RunspaceStateInfo.State -eq 'Opened') {
        $mouseStopper = [powershell]::Create()
        $mouseStopper.Runspace = $mouseRunspace
        $mouseStopper.AddScript({ [MouseHook]::Stop() }) | Out-Null
        $mouseStopper.Invoke()
        $mouseHandle.AsyncWaitHandle.WaitOne(500)
        $mouseRunspace.Close()
        $mouseRunspace.Dispose()
    }
    Write-Host "Terminé."
}

$null = 1 