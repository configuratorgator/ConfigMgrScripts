<#

.SYNOPSIS
Author: Brian Gade (@Configur8rGator, www.configuratorgator.com)

.DESCRIPTION
Compares computers in AD versus computers in ConfigMgr.  Removes computers that exist in ConfigMgr but not AD.

.PARAMETER CMPSModuleFile  
The full path to the ConfigurationManager.psd1 file that represents the ConfigMgr PowerShell module.
	Example:  "E:\Program Files\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1"

.PARAMETER LimitingCollectionName
The name of the Device Collection you want to use as a limiter.
	Example:  "All Client Devices"

.PARAMETER LogFile
The full path to the file you want to record to.  This is separate from the transcription file and is
meant to be a clean record of what machines were removed and when without all the extra bloat from
transcription.
	Example:  "E:\Program Files\Microsoft Configuration Manager\Logs\ScriptedADSync.log"

.PARAMETER SiteCode
Your ConfigMgr Site Code.
	Example:  "TST"

.PARAMETER TranscriptFile
The full path to the file you want transcription to record to.
	Example:  "E:\Program Files\Microsoft Configuration Manager\Logs\ScriptedADSync_Transcript.log"

.PARAMETER ExclusionList
A string array of machines to exclude from removal.  System-default devices (like the x86/x64 unknown devices) are excluded by default.
	Example: "Computer1","Computer2"

.EXAMPLE
.\ConfigMgr_AD_Cleanup.ps1 -CMPSModuleFile "C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1" -LimitingCollectionName "All Client Devices" -LogFile "C:\Program Files\Microsoft Configuration Manager\Logs\ScriptedADSync.log" -SiteCode "SND" -TranscriptFile "C:\Program Files\Microsoft Configuration Manager\Logs\ScriptedADSync_Transcript.log" -ExclusionList "SomeComputer1","SomeComputer2"

.NOTES
Change Log:
v1.0.0, ConfiguratorGator, 8/22/18 - Original Version
v1.0.1, ConfiguratorGator, 3/29/20 - Updated to include an exclusion list and fix some bugs

#>
# DEFINE PARAMETERS ----------------------------------------------
Param(
	[Parameter(Mandatory=$True)][string] $CMPSModuleFile,
	[Parameter(Mandatory=$True)][string] $LimitingCollectionName,
	[Parameter(Mandatory=$True)][string] $LogFile,
	[Parameter(Mandatory=$True)][string] $SiteCode,
	[Parameter(Mandatory=$True)][string] $TranscriptFile,
	[Parameter(Mandatory=$False)][string[]] $ExclusionList
)
# END DEFINE PARAMETERS ------------------------------------------
# IMPORT MODULES -------------------------------------------------

Import-Module ActiveDirectory
Import-Module $CMPSModuleFile

# END IMPORT MODULES ---------------------------------------------
# START TRANSCRIPTING --------------------------------------------
Start-Transcript -Path $TranscriptFile -Append -NoClobber
# DEFINE VARIABLES -----------------------------------------------

$ADComputers = @()
$CD = (Get-Location).Path
$ComputersNotInAD = @()
$ConfigWorkstations = @()
$SiteDrive = $SiteCode + ":\"
$SystemRequiredDevices = "Provisioning Device (Provisioning Device)","x64 Unknown Computer (x64 Unknown Computer)","x86 Unknown Computer (x86 Unknown Computer)"

# END DEFINE VARIABLES -------------------------------------------
# SCRIPT BODY ----------------------------------------------------

# Change to the ConfigMgr site
Set-Location $SiteDrive

# Get list of computers from AD and ConfigMgr
# For AD, get all enabled computer objects
# For ConfigMgr, get all computer objects from the specified collection except those in the system-required devices list
$ADComputers = Get-ADComputer -Filter {Enabled -eq $True} | Select-Object -Expand Name
$ConfigMgrWorkstations = Get-CMDevice -CollectionName $LimitingCollectionName | Where-Object{$_.Name -NotIn $SystemRequiredDevices} | Select-Object -Expand Name

# Compare the lists to find the ones in ConfigMgr but not AD
ForEach($Computer in $ConfigMgrWorkstations)
{
	# If the computer is in ConfigMgr but not AD, add it to the list of computers to remove
	If($Computer -NotIn $ADComputers)
	{
		$ComputersNotInAD += $Computer
	}
}

# Sort the array so it processes and logs alphabetically
$ComputersNotInAD = $ComputersNotInAD | Sort-Object

# Start the log file
$Now = Get-Date
"Computers removed from ConfigMgr on $Now" | Out-File -FilePath $LogFile -Append -NoClobber

# If there are no computers to clean up, log that
# Else remove the appropriate entries from ConfigMgr
If($Null -eq $ComputersNotInAD -or $ComputersNotInAD.Count -eq 0)
{
	Write-Host "No computers to remove"
	"N/A" | Out-File $LogFile -Append -NoClobber
}
Else
{
	ForEach($Computer in $ComputersNotInAD)
	{
		# If the computer is in the exclusion list, log that
		# Else remove it from ConfigMgr
		If($Computer -in $ExclusionList)
		{
			Write-Host "$Computer would have been removed if it were not in the exclusion list"
			"$Computer would have been removed if it were not in the exclusion list" | Out-File -FilePath $LogFile -Append -NoClobber
		}
		Else
		{
			Remove-CMDevice $Computer -Force
			Write-Host "$Computer was removed from ConfigMgr"
			"$Computer was removed from ConfigMgr" | Out-File -FilePath $LogFile -Append -NoClobber
		}
	}
}

# End the log file
"=========================================================" | Out-File -FilePath $LogFile -Append -NoClobber

# Return the prompt to the original location
Set-Location $CD

# END SCRIPT BODY ------------------------------------------------
# STOP TRANSCRIPTING ---------------------------------------------
Stop-Transcript
# END SCRIPT -----------------------------------------------------
# SIGNATURE ------------------------------------------------------