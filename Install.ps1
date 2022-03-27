if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

function Check-Command($cmdname) {
    return [bool](Get-Command -Name $cmdname -ErrorAction SilentlyContinue)
}

# -----------------------------------------------------------------------------
$computerName = Read-Host 'Enter New Computer Name'
Write-Host "Renaming this computer to: " $computerName  -ForegroundColor Yellow
Rename-Computer -NewName $computerName
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "Disable Sleep on AC Power..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
Powercfg /Change monitor-timeout-ac 20
Powercfg /Change standby-timeout-ac 0

# To list all appx packages:
# Get-AppxPackage | Format-Table -Property Name,Version,PackageFullName
Write-Host "Removing UWP Rubbish..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
$uwpRubbishApps = @(
    "Microsoft.Messaging",
    "king.com.CandyCrushSaga",
    "Microsoft.BingNews",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.People",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.MicrosoftOfficeHub",
    "Fitbit.FitbitCoach",
    "4DF9E0F8.Netflix",
    "Microsoft.GetHelp")

foreach ($uwp in $uwpRubbishApps) {
    Get-AppxPackage -Name $uwp | Remove-AppxPackage
}
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "Starting UWP apps to upgrade..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
$namespaceName = "root\cimv2\mdm\dmmap"
$className = "MDM_EnterpriseModernAppManagement_AppManagement01"
$wmiObj = Get-WmiObject -Namespace $namespaceName -Class $className
$result = $wmiObj.UpdateScanMethod()
# -----------------------------------------------------------------------------
if (Check-Command -cmdname 'choco') {
    Write-Host "Choco is already installed, skip installation."
}
else {
    Write-Host ""
    Write-Host "Installing Chocolate for Windows..." -ForegroundColor Green
    Write-Host "------------------------------------" -ForegroundColor Green
    Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

Write-Host ""
Write-Host "Installing Applications..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
Write-Host "[WARN] Ma de in China: some software like Google Chrome require the true Internet first" -ForegroundColor Yellow

$Apps = @(
    "7zip.install",
    "git",
    "nvidia-geforce-now",
    "greenshot",
    "chezmoi",
    "tailscale",
    "synctrayzor",
    "steam-client",
    "signal",
    "obs-studio",
    "obs-virtualcamera",
    "vscode",
    "winaero-tweaker",
    "mpvnet.install",
    "keybase",
    "github-desktop",
    "Firefox",
    "vivaldi",
    "ferdi",
    "chocolatelygui",
    "autohotkey",
    "1password",
    "alacritty",
    "googlechrome",
    "vlc",
    "sysinternals",
    "notepadplusplus.install",
    "nuget.commandline",
    "filezilla",
    "irfanview")

foreach ($app in $Apps) {
    choco install $app -y
}

Write-Host "Setting up Git for Windows..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
git config --global user.email "eric@alluvium.com"
git config --global user.name "Eric Reeves"
git config --global core.autocrlf true

Write-Host "Applying file explorer settings..." -ForegroundColor Green
cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v HideFileExt /t REG_DWORD /d 0 /f"
cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v AutoCheckSelect /t REG_DWORD /d 0 /f"
cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v LaunchTo /t REG_DWORD /d 1 /f"

Write-Host "Excluding repos from Windows Defender..." -ForegroundColor Green
Add-MpPreference -ExclusionPath "$env:USERPROFILE\source\repos"
Add-MpPreference -ExclusionPath "$env:USERPROFILE\.nuget"
Add-MpPreference -ExclusionPath "$env:USERPROFILE\.vscode"
Add-MpPreference -ExclusionPath "$env:USERPROFILE\.dotnet"
Add-MpPreference -ExclusionPath "$env:USERPROFILE\.ssh"
Add-MpPreference -ExclusionPath "$env:APPDATA\npm"

# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "Checking Windows updates..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
Install-Module -Name PSWindowsUpdate -Force
Write-Host "Installing updates... (Computer will reboot in minutes...)" -ForegroundColor Green
Get-WindowsUpdate -AcceptAll -Install -ForceInstall -AutoReboot

# -----------------------------------------------------------------------------
Write-Host "------------------------------------" -ForegroundColor Green
Read-Host -Prompt "Setup is done, restart is needed, press [ENTER] to restart computer."
Restart-Computer
