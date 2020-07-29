<#

.SYNOPSIS
Author: Brian Gade (@Configur8rGator, www.configuratorgator.com)

.DESCRIPTION
Generates a random key file for use with PowerShell string encryption

.PARAMETER OutputFile
The file path and name to the file to output

.EXAMPLE
.\Create_Key_File.ps1 -OutputFile "$ENV:UserProfile\Desktop\Key.key"

.NOTES
Change log:
v1.0.0, ConfiguratorGator, 6/5/19 - Original Version

#>
# DEFINE PARAMETERS ----------------------------------------------
Param(
    [Parameter(Mandatory=$True)]
    [string] $OutputFile
)
# END DEFINE PARAMETERS ------------------------------------------
# DEFINE VARIABLES -----------------------------------------------

$Key = New-Object Byte[] 32

# END DEFINE VARIABLES -------------------------------------------
# SCRIPT BODY ----------------------------------------------------

[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Key)
$Key | Out-File $OutputFile -Force

# END SCRIPT BODY ------------------------------------------------
# END SCRIPT -----------------------------------------------------
# SIGNATURE ------------------------------------------------------
