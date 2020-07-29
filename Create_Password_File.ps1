<#

.SYNOPSIS
Author: Brian Gade (@Configur8rGator, www.configuratorgator.com)

.DESCRIPTION
Encrypts a password using a key file

.PARAMETER KeyFile
The file path and name of the key file to use for encryption

.PARAMETER OutputFile
The file path and name to the file to output

.PARAMETER Password
The password to encrypt, in plain text

.EXAMPLE
.\Create_Password_File.ps1 -KeyFile "$ENV:UserProfile\Desktop\Key.key" -OutputFile "$ENV:UserProfile\Desktop\Password.txt" -Password Pa$$w0rd

.NOTES
Change log:
v1.0.0, ConfiguratorGator, 6/5/19 - Original Version

#>
# DEFINE PARAMETERS ----------------------------------------------
Param(
    [Parameter(Mandatory=$True)]
    [string] $KeyFile,
    [Parameter(Mandatory=$True)]
    [string] $OutputFile,
    [Parameter(Mandatory=$True)]
    [String] $Password
)
# END DEFINE PARAMETERS ------------------------------------------
# SCRIPT BODY ----------------------------------------------------

$Key = Get-Content $KeyFile
$SecurePassword = $Password | ConvertTo-SecureString -AsPlainText -Force
$SecurePassword | ConvertFrom-SecureString -Key $Key | Out-File $OutputFile -Force

# END SCRIPT BODY ------------------------------------------------
# END SCRIPT -----------------------------------------------------
# SIGNATURE ------------------------------------------------------