<#

.SYNOPSIS
Author: Brian Gade (@Configur8rGator, www.configuratorgator.com)

.DESCRIPTION
Checks to see whether the device is connected to a CMG-only boundary group (based on a list you specify).  
If so, updates WMI so the Task Sequence Engine believes the client is operating as "currently internet."
This is done to work around a current bug in ConfigMgr where it still looks for an on-prem DP when a client is in a CMG-only boundary group and has domain connectivity.

.EXAMPLE
.\UpdateWMI.ps1

.NOTES
Change log:
v1.0.0, ConfiguratorGator, 7/7/2020 - Original Version

#>
# DEFINE VARIABLES -----------------------------------------------

$CMG_Only_BoundaryGroups = "16777123,16777234"
$CurrentBoundaryGroupIDs = Get-WmiObject -Namespace root\ccm\LocationServices -Class BoundaryGroupCache | Select-Object -Expand BoundaryGroupIDs
$UpdateWMI = $False

# END DEFINE VARIABLES -------------------------------------------
# SCRIPT BODY ----------------------------------------------------

# Enforce English output
[Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'

# If the client is in any CMG-only boundary group, set UpdateWMI to True
ForEach($BoundaryGroupID in $CurrentBoundaryGroupIDs)
{
    If($CMG_Only_BoundaryGroups -Contains $BoundaryGroupID)
    {
        $UpdateWMI = $True
    }
}

# If UpdateWMI is True, update WMI
If($UpdateWMI -eq $True)
{
    # Update WMI so the task sequence engine believes the ConfigMgr client is in Internet mode
    $ClientInfo = Get-WmiObject -Namespace root\ccm -Class ClientInfo
    $ClientInfo.InInternet = $True
    $ClientInfo.Put()
}

# END SCRIPT BODY ------------------------------------------------
# END SCRIPT -----------------------------------------------------
# SIGNATURE ------------------------------------------------------