#requires -version 4

<#
.SYNOPSIS
  Script to seal the a Windows Golden image in a VDI environment.

.DESCRIPTION
  Windows generates a lot of space and configuration.  In a VDI environment, speed and space are everything.  This will release
  all the network information that is stored in Windows and clean up all unused space.  

  This script also relies on SDELETE being loaded into the image.  This will help zero out and release disk space that has been 
  consumed by the image.  The download can be found: https://docs.microsoft.com/en-us/sysinternals/downloads/sdelete

.INPUTS None
  There script takes no inputs

.MODULES
This script requires the logging module PSLogging.  The module can be installed using the standard install-module or download from
the github site: https://github.com/9to5IT/PSLogging.  

.OUTPUTS Log File
  The script log file stored in C:\Windows\Temp\<name>.log

.NOTES
  Version:        1.0
  Author:         Joseph Zavcer
  Creation Date:  3/23/2018
  Purpose/Change: Initial script development

.EXAMPLE
  PS >.\Invoke-Finalizer
#>

#---------------------------------------------------------[Script Parameters]------------------------------------------------------

Param (
    #Script parameters go here
    #[Parameter(Mandatory = $false, Position = 0, HelpMessage = 'HELP')]
    #[AllowNull()]
    #[string]$Setting = ""
)

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

#Set Error Action to Silently Continue
$ErrorActionPreference = 'SilentlyContinue'

#Import Modules & Snap-ins
Import-Module PSLogging

#----------------------------------------------------------[Declarations]----------------------------------------------------------

#Script Version
$sScriptVersion = '1.0'

# temp folders
$tempfolders = $null

#Log File Info
$sLogPath = 'C:\Windows\Temp'
$sLogName = 'Finalizer.log'
$sLogFile = Join-Path -Path $sLogPath -ChildPath $sLogName

#-----------------------------------------------------------[Functions]------------------------------------------------------------

<#
    No locally defined functions
#>

#-----------------------------------------------------------[Execution]------------------------------------------------------------

Start-Log -LogPath $sLogPath -LogName $sLogName -ScriptVersion $sScriptVersion

# this section of the code will shutdown the Windows Update Service.  Later on the SoftwareDistribution folder will be deleted.  Hopefully
# this fixes most of the issues with Windows Updates.
try {
    $service = Get-WmiObject Win32_Service -Filter 'Name="wuauserv"'
    if ($service) {
        if ($service.State -eq "Running") {
            $result = $service.StopService().ReturnValue
            if ($result) {
                Write-LogError -LogPath $sLogFile -Message "Failed to stop the 'wuauserv' service on $_. The return value was $result."
            }
            else {
                Write-LogInfo -LogPath $sLogFile -Message "Success to stop the 'wuauserv' service on $_."
            }
        }      
    }
    else {
        Write-LogError -LogPath $sLogFile -Message "Failed to retrieve the service 'wuauserv' from $_."
    }
}
catch {
    # log the error
    Write-LogInfo -LogPath $sLogFile -Message "Something unexpected occured while trying to execute the SEP Live Update"
    Write-LogError -LogPath $sLogFile -Message $_.Exception.GetType().FullName
    Write-LogError -LogPath $sLogFile -Message $_.Exception.Message
}

# Remove all the temporary files/folders
try {

    $tempfolders = @("C:\Windows\Temp\*", "C:\Windows\Prefetch\*", "C:\Documents and Settings\*\Local Settings\temp\*", "C:\Users\*\Appdata\Local\Temp\*", "C:\Windows\SoftwareDistribution\*")
    Write-LogInfo -LogPath $sLogFile -Message "Cleaning up all the temp folders"  
    Remove-Item $tempfolders -Force -Recurse -ErrorAction "SilentlyContinue"  
}
catch {
    # log the error
    Write-LogInfo -LogPath $sLogFile -Message "Something unexpected occured while trying to clear the temp folders"
    Write-LogError -LogPath $sLogFile -Message $_.Exception.GetType().FullName
    Write-LogError -LogPath $sLogFile -Message $_.Exception.Message
}

# execute disk cleanup
try {
	Write-LogInfo -LogPath $sLogFile -Message "Clearing any previous CleanMgr.exe automation settings"
	Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\*' -Name StateFlags0001 -ErrorAction SilentlyContinue | Remove-ItemProperty -Name StateFlags0001 -ErrorAction SilentlyContinue

	# create the necessary registry entries for the disk cleanup
	Write-LogInfo -LogPath $sLogFile -Message "Configuring CleanMgr.exe automation settings"
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Internet Cache Files' -Name StateFlags0001 -Value 2 -PropertyType DWord
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup' -Name StateFlags0001 -Value 2 -PropertyType DWord
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files' -Name StateFlags0001 -Value 2 -PropertyType DWord
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Files' -Name StateFlags0001 -Value 2 -PropertyType DWord
	
	# start the automated process, and wait for it to finish
	Write-LogInfo -LogPath $sLogFile -Message "Starting new process for cleanmgr.exe"
	Start-Process -FilePath CleanMgr.exe -ArgumentList "/sagerun:1" -WindowStyle Hidden -Wait 
}
catch {
	Write-LogInfo -LogPath $sLogFile -Message "Something unexpected occured while trying to perform disk cleanup"
	Write-LogError -LogPath $sLogFile -Message $_.Exception.GetType().FullName
	Write-LogError -LogPath $sLogFile -Message $_.Exception.Message
}

# Starting the defrag process
try {
    Write-LogInfo -LogPath $sLogFile -Message "Executing a defrag on the C: to reduce space on the image"
    Start-Process -FilePath "Defrag" -ArgumentList "c: -f" -Wait
}
catch {
    # log the error
    Write-LogInfo -LogPath $sLogFile -Message "Something unexpected occured while trying to execute a defrag on the system drive"
    Write-LogError -LogPath $sLogFile -Message $_.Exception.GetType().FullName
    Write-LogError -LogPath $sLogFile -Message $_.Exception.Message
}

# Starting the zero out process
try {
    Write-LogInfo -LogPath $sLogFile -Message "Setting all active space to zero"
    Start-Process -FilePath "sdelete64.exe" -WorkingDirectory "C:\Windows\System32\" -ArgumentList "-z c:" -Verb RunAs -Wait
}
catch {
    # log the error
    Write-LogInfo -LogPath $sLogFile -Message "Something unexpected occured while trying to execute a SDelete on the system drive"
    Write-LogError -LogPath $sLogFile -Message $_.Exception.GetType().FullName
    Write-LogError -LogPath $sLogFile -Message $_.Exception.Message
}


# cleaning up the network
try {
    Write-LogInfo -LogPath $sLogFile -Message "Removing the current network configuration, flushing dns, and clearing the arp tables"
    Start-Process -FilePath "$env:SystemRoot\System32\ipconfig.exe" -ArgumentList "/flushdns" -Verb "RunAs" -WindowStyle Hidden -Wait
    Start-Process -FilePath "$env:SystemRoot\System32\ipconfig.exe" -ArgumentList "/releaseall" -Verb "RunAs" -WindowStyle Hidden -Wait
    Start-Process -FilePath "$env:SystemRoot\System32\netsh.exe" -ArgumentList "interface ip delete arpcache" -Verb "RunAs" -WindowStyle Hidden -Wait
}
catch {
    # log the error
    Write-LogInfo -LogPath $sLogFile -Message "Something unexpected occured while trying reset the network"
    Write-LogError -LogPath $sLogFile -Message $_.Exception.GetType().FullName
    Write-LogError -LogPath $sLogFile -Message $_.Exception.Message
}

Write-LogInfo -LogPath $sLogFile -Message "Finalization complete for golden image $($env:COMPUTERNAME), shutting down the virtual desktop"
Write-LogInfo -LogPath $sLogFile -Message "Stopping script execution." 

#clears the event log to get rid of all the old events.
$EventLogs = Get-EventLog -List | Where-Object { $_.Log -match "Application|Security|System"} | ForEach-Object {$_.Log}
$EventLogs | ForEach-Object -Process {
    Write-LogInfo -LogPath $sLogFile -Message "Clearing Windows Event Log: $_."
    try{
        Clear-EventLog -Log $_ 
    }
    catch{
        Write-LogInfo -LogPath $sLogFile -Message "Something unexpected occured while trying to clear $_ log"
        Write-LogError -LogPath $sLogFile -Message $_.Exception.GetType().FullName
        Write-LogError -LogPath $sLogFile -Message $_.Exception.Message
    }
}

Stop-Log -LogPath $sLogFile

# Shutdown the computer
Stop-Computer -Confirm:$false