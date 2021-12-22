<#

.SYNOPSIS
Author: Brian Gade (@Configur8rGator, www.configuratorgator.com)

.DESCRIPTION
Renews the certificates used by ConfigMgr DPs, MPs, SMPs, and/or SUPs, provided they are not already expired.
Updates IIS to use the renewed certificate.
Exports the new DP certificate and configures the DP to use that certificate (i.e. for during PXE).  Finally,
updates ConfigMgr to unblock any applicable DP certificates. This is done to accommodate for certificate
expiration/renewal.
Requires a separate script on each target server that perform the certificate renewal. This script will attempt
to create that script if it doesn't exist and if the target server's Execution Policy is not set to AllSigned.
However, you should really create the script (with transcripting), sign it, and make it accessible to each
server.  Note that this code assumes you're using SAN data in your certs with
two DNS entries (server name and server FQDN) and that the only certificates that meet this criteria on that
server are the ones used for ConfigMgr.

PREREQUISITES AND ASSUMPTIONS:
1. The ConfigMgr console is installed on the computer running this script
2. The account running the script has appropriate permissions within ConfigMgr
3. The existing certificates have exactly two entries in the DNS Name portion of the Subject Alternative Name
4. The Distribution Point servers have a D drive that can be written to
    a. This can easily be changed in the UpdateDistributionPointCertificate function
5. The IIS bindings are not limited to specific IPs
    a. This can easily be changed in the UpdateWebServerCertificate function
6. If your servers allow unsigned PowerShell to run, this script will do everything for you.  If they only allow signed code,
    you, will need to place a signed copy of the code defined in the $RenewalScriptCode variable on each server and pass that
    location into the CertRenewalScriptPath parameter    

.PARAMETER CertPassword
String.  The plain-text password to use when exporting the Distibution Point certificate.

.PARAMETER CertRenewalScriptPath
String.  The path to the script used to renew the certificates.  The computer account of each targer server
must have access to this path.  A local path is recommended.

.PARAMETER ConfigMgrServerFQDN
String.  The fully-qualified name of ConfigMgr's primary site server.

.PARAMETER ConfigMgrSiteCode
String.  The ConfigMgr site code.

.PARAMETER DomainFQDN
String.  The full domain name (i.e. contoso.com).

.PARAMETER ScheduledTaskName
String.  The name to assign to the scheduled task that will be created to run the script at CertRenewalScriptPath.

.PARAMETER DPOnly
Switch.  Only process Distribution Point servers/roles.  If any target server also runs the Management Point
or Software Update Point role, do not select this switch (because the certificates will be updated but IIS
will not).

.PARAMETER MPOnly
Switch.  Only process Management Point servers/roles.  If any target server also runs the Software Update Point role,
do not select this switch (because the certificates will be updated but IIS will not).

.PARAMETER SMPOnly
Switch.  Only process State Migration Point servers/roles.  If any target server also runs the Software Update Point role,
do not select this switch (because the certificates will be updated but IIS will not).

.PARAMETER SUPOnly
Switch.  Only process Software Update Point servers/roles.  If any target server also runs the Management Point role,
do not select this switch (because the certificates will be updated but IIS will not).

.PARAMETER ReallyVerbose
Switch.  This script enables the native Verbose switch for its own output but attempts to disable verbose output of
external cmdlets by default.  To enable verbose output for this script only, use Verbose.  To enable verbose output
for this script and the external cmdlets it calls, use ReallyVerbose.  Using ReallyVerbose implies Verbose.

.EXAMPLE
.\Update_ConfigMgr_Certificates.ps1 -CertPassword Pa$$w0rd -ConfigMgrServerFQDN SC01.sandbox.local -ConfigMgrSiteCode SND -DomainFQDN sandbox.local -CertRenewalScriptPath "D:\AdminFiles\Renew_ConfigMgr_Certificates.ps1" -ScheduledTaskName "Renew ConfigMgr Certs"

.NOTES

Change log:
v2021.12.22.1, Brian Gade - Original Version

#>
# DEFINE PARAMETERS ----------------------------------------------
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True)]
        [string] $CertPassword,
    [Parameter(Mandatory=$True)]
        [string] $CertRenewalScriptPath,
    [Parameter(Mandatory=$True)]
        [string] $ConfigMgrServerFQDN,
    [Parameter(Mandatory=$True)]
        [string] $ConfigMgrSiteCode,
    [Parameter(Mandatory=$True)]
        [string] $DomainFQDN,
    [Parameter(Mandatory=$True)]
        [string] $ScheduledTaskName,
	[Parameter(Mandatory=$False)]
        [switch] $DPOnly,
    [Parameter(Mandatory=$False)]
        [switch] $MPOnly,
    [Parameter(Mandatory=$False)]
        [switch] $SMPOnly,
    [Parameter(Mandatory=$False)]
        [switch] $SUPOnly,
    [Parameter(Mandatory=$False)]
        [switch] $ReallyVerbose
)

# If ReallyVerbose is chosen, automatically enable standard verbose
If($ReallyVerbose -eq $True)
{
    $VerbosePreference = "Continue"
}

# END DEFINE PARAMETERS ------------------------------------------
# START TRANSCRIPTING --------------------------------------------
$TranscriptLogFile = '.\Update_ConfigMgr_Certificates_Transcript.log'
Start-Transcript -Path $TranscriptLogFile -Append -NoClobber
# LOAD MODULES ---------------------------------------------------

Write-Host "Importing the ConfigMgr module..." -ForegroundColor Green
Import-Module (Join-Path $(Split-Path $env:SMS_ADMIN_UI_PATH) ConfigurationManager.psd1) -Verbose:$ReallyVerbose

# END LOAD MODULES -----------------------------------------------
# DEFINE CLASSES -------------------------------------------------

Write-Host "Defining the custom class..." -ForegroundColor Green
Class DPCertInfo
{
	[string] $DPName
	[string] $CertFileName
}

# END DEFINE CLASSES ---------------------------------------------
# DEFINE VARIABLES -----------------------------------------------

$Attempts = 1
$CD = (Get-Location).Path
$CMPSSuppressFastNotUsedCheck = $True
$ConfigMgr_Server = $ConfigMgrServerFQDN
$ConfigMgr_SiteCode = $ConfigMgrSiteCode
$ConfigMgr_SiteDrive = $ConfigMgr_SiteCode + ":\"
$DomainSuffix = "." + "$DomainFQDN"
$DPCerts = @()
$IIS_AppID = "{4dc3e181-e14b-4a21-b022-59fc669b0914}"
$IIS_Port_DP = "443"
$IIS_Port_MP = "443"
$IIS_Port_SMP = "443"
$IIS_Port_SUP = "8531"
$MaxAttempts = 100
$RenewalScriptCode = '# Get the current SCCM Distribution Point certificate
$DPCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object{$_.DnsNameList.Count -eq 2 -and $_.EnhancedKeyUsageList -like "*Client Authentication*"}

# Renew the SCCM Distribution Point certificate
certreq -enroll -machine -q -PolicyServer * -cert $($DPCert.SerialNumber) renew

# Get the current SCCM Web Server certificate
$WebServerCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object{$_.DnsNameList.Count -eq 2 -and $_.EnhancedKeyUsageList -like "*Server Authentication*"}

# Renew the SCCM Web Server certificate
certreq -enroll -machine -q -PolicyServer * -cert $($WebServerCert.SerialNumber) renew'
$RenewedCerts = 0
$ScheduledTaskPath = "\" + "$DomainFQDN" + "\"
$ScheduledTaskXML = '<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2020-08-03T10:11:03.7258973</Date>
    <Author>ConfiguratorGator</Author>
    <URI>\MYDOMAIN\MYTASKNAME</URI>
  </RegistrationInfo>
  <Triggers />
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command>
      <Arguments>MYSCRIPTPATH</Arguments>
    </Exec>
  </Actions>
</Task>'
$ScheduledTaskXML = $ScheduledTaskXML -Replace "MYDOMAIN",$DomainFQDN -Replace "MYSCRIPTPATH",$CertRenewalScriptPath -Replace "MYTASKNAME",$ScheduledTaskName

# END DEFINE VARIABLES -------------------------------------------
# DEFINE FUNCTIONS -----------------------------------------------

# Function to perform certificate renewal
Function RenewCertificates([string] $ServerName, [string] $ScheduledTaskPath, [string] $ScheduledTaskName, [string] $ScheduledTaskXML, [string] $CertRenewalScriptPath, [string] $RenewalScriptCode)
{
    Invoke-Command -ComputerName $ServerName -ScriptBlock {
        # If the target script doesn't exist and the execution policy is set to AllSigned, throw an error
        # ElseIf the target script doesn't exist and the execution policy is not AllSigned, create the folder and script
        If((Test-Path "FileSystem::$($Using:CertRenewalScriptPath)") -eq $False -and (Get-ExecutionPolicy) -eq "AllSigned")
        {
            # Throw an error
            Throw "`"$Using:CertRenewalScriptPath`" is not accessible on server $Using:ServerName, and cannot be created due to the Execution Policy! Please install a signed copy of the script and try again."
        }
        ElseIf((Test-Path "FileSystem::$($Using:CertRenewalScriptPath)") -eq $False -and (Get-ExecutionPolicy) -ne "AllSigned")
        {
            # Determine where to store the script
            $ScriptSplit = $Using:CertRenewalScriptPath -Split "\\"
            $Index = $ScriptSplit.Count - 2
            $ScriptFolder = $ScriptSplit[0..$Index] -Join "\"
            $ScriptName = $ScriptSplit[($Index + 1)]

            # If the folder doesn't exist, create it
            If((Test-Path "FileSystem::$ScriptFolder") -eq $False)
            {
                Write-Verbose "Attempting to create the folder for the renewal script..."
                New-Item -ItemType Directory -Path $ScriptFolder -Force | Out-Null
            }

            # If creating the folder was successful, create the script inside it
            If((Test-Path "FileSystem::$ScriptFolder") -eq $True)
            {
                # Set the target file name
                $ScriptFile = $ScriptFolder + "\" + $ScriptName

                # Create the script
                Write-Verbose "Attempting to create the renewal script..."
                $Using:RenewalScriptCode | Out-File -FilePath $ScriptFile -Force

                # If creating the file failed, throw an error
                If((Test-Path "FileSystem::$ScriptFile") -eq $False)
                {
                    Throw "Unable to create $ScriptFile on $Using:ServerName!"
                }
            }
            Else
            {
                # Throw an error
                Throw "Unable to create $ScriptFolder on $Using:ServerName!"
            }
        }
        
        # Create the scheduled task
        Register-ScheduledTask -XML $Using:ScheduledTaskXML -TaskPath $Using:ScheduledTaskPath -TaskName $Using:ScheduledTaskName -Force | Out-Null

        # Start the scheduled task to renew the ConfigMgr certificates and wait for it to finish
        Start-ScheduledTask -TaskPath $Using:ScheduledTaskPath -TaskName $Using:ScheduledTaskName
        While((Get-ScheduledTask -TaskPath $Using:ScheduledTaskPath -TaskName $Using:ScheduledTaskName).State -ne "Ready")
        {
            # Wait five seconds
            Start-Sleep -Seconds 5
        }
    }
}

# Function to export the new Distribution Point certificate, including the private key
Function UpdateDistributionPointCertificate([string] $ServerName, [string] $CertPassword)
{
    $ExportName = Invoke-Command -ComputerName $ServerName -ScriptBlock {
        # Convert the plain-text password to a secure string
        $SecureCertPassword = $Using:CertPassword | ConvertTo-SecureString -AsPlainText -Force

        # Get the current ConfigMgr Distribution Point certificate
        $DPCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object{$_.DnsNameList.Count -eq 2 -and $_.EnhancedKeyUsageList -like "*Client Authentication*"}

        # Make sure we got a cert
        If($Null -ne $DPCert)
        {
            # Export the certificate to a file
	    	$Export = Export-PfxCertificate -Cert $DPCert -FilePath "D:\$($ENV:ComputerName)_DPCert_Exp_$(Get-Date $DPCert.NotAfter -Format MMddyy).pfx" -Password $SecureCertPassword -Force

            # Return the filename of the exported file
            Return $($Export.Name)
        }
        Else
        {
            Return $Null
        }
	}

    # Inform the user
    # If we got data back, add it to the array
	If($Null -ne $ExportName)
	{
        Write-Host "Successfully got cert export info for $ServerName" -ForegroundColor Green
        Write-Verbose "ExportName: $ExportName"
        $Script:DPCerts += New-Object DPCertInfo -Property @{DPName="$ServerName"; CertFileName="$ExportName"}
	}
	Else
	{
		Write-Host "Unable to get cert export info for $ServerName" -ForegroundColor Red
	}
}

# Function to update the certificate within IIS
Function UpdateWebServerCertificate([string] $ServerName, [string] $IIS_AppID, [string] $PortNumber)
{
    $WebServerResult = Invoke-Command -ComputerName $ServerName -ScriptBlock {
        # Get the current ConfigMgr Web Server certificate
        $WebServerCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object{$_.DnsNameList.Count -eq 2 -and $_.EnhancedKeyUsageList -like "*Server Authentication*"}

        # Check for an existing binding
        $ExistingBinding = netsh http show sslcert IPPort="0.0.0.0:$Using:PortNumber"

        # If a binding exists, update it
        # Else display a message
        If($ExistingBinding -like "*Certificate Hash*")
        {
            # Update IIS to use the renewed certificate
            netsh http update sslcert IPPort="0.0.0.0:$Using:PortNumber" CertHash=$($WebServerCert.Thumbprint) AppID=$Using:IIS_AppID
        }
        Else
        {
            # Display a message
            Return "Binding not present"
        }        
    }

    # Inform the user whether the IIS update was successful
    If($WebServerResult -like "*SSL Certificate successfully updated*")
    {
        Write-Host "Successfully updated the ConfigMgr Web Server Certificate for $ServerName." -ForegroundColor Green
        Write-Verbose $WebServerResult.ToString() -ErrorAction SilentlyContinue
    }
    ElseIf($WebServerResult -like "*Binding not present*")
    {
        Write-Host "Failed to update IIS because no binding exists for port $PortNumber on $ServerName!" -ForegroundColor Red
        Write-Verbose $WebServerResult.ToString() -ErrorAction SilentlyContinue
    }
    Else
    {
        Write-Host "Failed to update IIS to use the current ConfigMgr Web Server certificate for $ServerName!  This must be done manually!" -ForegroundColor Red
        Write-Verbose $WebServerResult.ToString() -ErrorAction SilentlyContinue
    }
}

# END DEFINE FUNCTIONS -------------------------------------------
# SCRIPT BODY ----------------------------------------------------

# Verify connection to ConfigMgr
Write-Host "Checking connection to ConfigMgr..." -ForegroundColor Green
$DriveTest = Get-PSDrive $ConfigMgr_SiteCode -ErrorAction SilentlyContinue -Verbose:$ReallyVerbose

# If the connection wasn't verified, retry it
While($Null -eq $DriveTest -and $Attempts -lt $MaxAttempts)
{
    Start-Sleep -Seconds 2
	Write-Verbose "Attempting to connect to ConfigMgr (Attempt $Attempts of $MaxAttempts)..." -ForegroundColor Green
    New-PSDrive -Name $ConfigMgr_SiteCode -PSProvider CMSite -Root $ConfigMgr_Server -Verbose:$ReallyVerbose | Out-Null
    $DriveTest = Get-PSDrive $ConfigMgr_SiteCode -ErrorAction SilentlyContinue -Verbose:$ReallyVerbose
    $Attempts ++
}

# If we failed to connect to ConfigMgr, throw an error
If($Attempts -ge $MaxAttempts)
{
    # Throw an error and quit
    Throw "Unable to connect to ConfigMgr!"
    Return
}

# Change directory to the site drive
Set-Location $ConfigMgr_SiteDrive

# Get the list of servers from ConfigMgr
Write-Host "Getting the list of on-prem DPs..." -ForegroundColor Green
$DPs = Get-CMDistributionPoint -Verbose:$ReallyVerbose | Where-Object{$_.NetworkOSPath -like "*$DomainSuffix"} | Select-Object -Expand NetworkOSPath
$DPs = $DPs -Replace "\\\\",""
Write-Verbose "DPs: $DPs"
Write-Host "Getting the list of on-prem MPs..." -ForegroundColor Green
$MPs = Get-CMManagementPoint -Verbose:$ReallyVerbose | Where-Object{$_.NetworkOSPath -like "*$DomainSuffix"} | Select-Object -Expand NetworkOSPath
$MPs = $MPs -Replace "\\\\",""
Write-Verbose "MPs: $MPs"
Write-Host "Getting the list of on-prem SMPs..." -ForegroundColor Green
$SMPs = Get-CMStateMigrationPoint -Verbose:$ReallyVerbose | Where-Object{$_.NetworkOSPath -like "*$DomainSuffix"} | Select-Object -Expand NetworkOSPath
$SMPs = $SMPs -Replace "\\\\",""
$SMPs = $SMPs | Where-Object{$_ -NotIn $DPs} # Remove SMPs that are also DPs, since their certs will already get processed during the DP phase
Write-Verbose "SMPs: $SMPs"
Write-Host "Getting the list of on-prem SUPs..." -ForegroundColor Green
$SUPs = Get-CMSoftwareUpdatePoint -Verbose:$ReallyVerbose | Where-Object{$_.NetworkOSPath -like "*$DomainSuffix"} | Select-Object -Expand NetworkOSPath
$SUPs = $SUPs -Replace "\\\\",""
Write-Verbose "SUPs: $SUPs"

# Build the full server list
$FullServerList = $DPs + $MPs + $SMPs + $SUPs | Select-Object -Unique | Sort-Object
Write-Verbose "Full Server List: $FullServerList"

# On each server, renew the certificates
ForEach($Server in $FullServerList)
{
    # Update the user
    Write-Host "Processing $Server..." -ForegroundColor Green

    # Reset loop variables
    $CertsRenewed = $False

    # Renew the certificates on the target server
    # This uses a scheduled task on the target server because using Invoke-Command results in an error about the user account not being authenticated
    Try
    {
        # Renew the certificates on the target server
        Write-Host "Waiting for $Server to renew its ConfigMgr certificates.  This could take a few minutes..." -ForegroundColor Green
        RenewCertificates -ServerName $Server -ScheduledTaskPath $ScheduledTaskPath -ScheduledTaskName $ScheduledTaskName -ScheduledTaskXML $ScheduledTaskXML -CertRenewalScriptPath $CertRenewalScriptPath -RenewalScriptCode $RenewalScriptCode
        
        # Set the variable that indicates renewal was successful
        $CertsRenewed = $True

        # Increment the counter
        $RenewedCerts ++
    }
    Catch
    {
        Write-Host "Failed to renew the certificates for $Server!" -ForegroundColor Red
        Write-Verbose $_
    }

    # Only proceed if the certificates were successfully renewed
    If($CertsRenewed -eq $True)
    {
        # If the server is a Distribution Point, update IIS to use the new cert and export the new cert
        If($DPs -Contains $Server -and $MPOnly -ne $True -and $SMPOnly -ne $True -and $SUPOnly -ne $True)
        {
            # Update IIS to use the renewed certificates for the HTTPS binding
            Write-Host "Updating the DP's Web Server Certificate in IIS..." -ForegroundColor Green
            UpdateWebServerCertificate -ServerName $Server -IIS_AppID $IIS_AppID -PortNumber $IIS_Port_DP

            # Export the DP certificate to a local path on the target server and get that path into a variable
            Write-Host "Exporting the new Distribution Point Certificate to PFX..." -ForegroundColor Green
            UpdateDistributionPointCertificate -ServerName $Server -CertPassword $CertPassword

            # Update the DP's configuration in ConfigMgr
            Try
            {
                # Inform the user
                Write-Host "Updating DP config in ConfigMgr for $Server..." -ForegroundColor Green

                # Set the variable for the certificate's location for use in ConfigMgr
                $PathRoot = "\\" + ($Server -Replace $DomainSuffix,"") + "\D$"
                Write-Verbose "PathRoot: $PathRoot"

                # Get the data from the array
                $CertInfo = $DPCerts | Where-Object{$_.DPName -eq $Server}
                Write-Verbose "CertInfo: $($CertInfo.ToString())"

                # Get the certificate
                $CertPath = "$PathRoot\$($CertInfo.CertFileName)"
                Write-Verbose "CertPath: $CertPath"

                #Verify the certificate is accessible
                If($CertPath -NotLike "*.pfx")
                {
                    # Target file is not a PFX certificate
                    Throw "CertPath is not a PFX!"
                }
                ElseIf((Test-Path "FileSystem::$CertPath") -eq $False)
                {
                    # Target file is not accessible
                    Throw "Unable to access `"$CertPath`"!"
                }
                Else
                {
                    # Get the DP from ConfigMgr
                    $DP = Get-CMDistributionPoint -SiteSystemServerName $Server -Verbose:$ReallyVerbose

                    # Convert the plain-text password to a securestring
                    $DPCertPassword = $CertPassword | ConvertTo-SecureString -AsPlainText -Force

                    # Update the DP config
                    Set-CMDistributionPoint -DistributionPoint $DP -CertificatePath $CertPath -CertificatePassword $DPCertPassword -Force -Verbose:$ReallyVerbose
                }
            }
            Catch
            {
                # Inform the user there was an error and show the exception
                Write-Host "Failed to update DP $Server in ConfigMgr!" -ForegroundColor Red
                Write-Verbose $_
            }
        }

        # If the server is a Management Point, update IIS to use the new cert
        If($MPs -Contains $Server -and $DPOnly -ne $True -and $SMPOnly -ne $True -and $SUPOnly -ne $True)
        {
            # Update IIS to use the renewed certificates for the HTTPS binding
            Write-Host "Updating the MP's Web Server Certificate in IIS..." -ForegroundColor Green
            UpdateWebServerCertificate -ServerName $Server -IIS_AppID $IIS_AppID -PortNumber $IIS_Port_MP
        }

        # If the server is a State Migration Point, update IIS to use the new cert
        If($SMPs -Contains $Server -and $DPOnly -ne $True -and $MPOnly -ne $True -and $SUPOnly -ne $True)
        {
            # Update IIS to use the renewed certificates for the HTTPS binding
            Write-Host "Updating the SMP's Web Server Certificate in IIS..." -ForegroundColor Green
            UpdateWebServerCertificate -ServerName $Server -IIS_AppID $IIS_AppID -PortNumber $IIS_Port_SMP
        }
        
        # If the server is a Software Update Point, update IIS to use the new cert
        If($SUPs -Contains $Server -and $DPOnly -ne $True -and $MPOnly -ne $True -and $SMPOnly -ne $True)
        {
            # Update IIS to use the renewed certificates for the HTTPS binding
            Write-Host "Updating the SUP's Web Server Certificate in IIS..." -ForegroundColor Green
            UpdateWebServerCertificate -ServerName $Server -IIS_AppID $IIS_AppID -PortNumber $IIS_Port_SUP
        }
    }
}

# If at least one certificate was renewed and we updated a DP, proceed
If($RenewedCerts -gt 0 -and $MPOnly -ne $True -and $SMPOnly -ne $True -and $SUPOnly -ne $True)
{
    # Unblock the DP certificates in ConfigMgr
    # Get all the certificates of type Distribution Point that are blocked but not expired
    Write-Host "Waiting 60 seconds before unblocking certificates in ConfigMgr..." -ForegroundColor Green
    Start-Sleep -Seconds 60
    Write-Host "Unblocking certificates in ConfigMgr..." -ForegroundColor Green
    $BlockedCerts = Get-CMCertificate -Verbose:$ReallyVerbose | Where-Object{$_.IsBlocked -eq $True -and $_.Type -eq 2 -and $_.ValidUntil -gt (Get-Date)}
    ForEach($Cert in $BlockedCerts)
    {
        Unblock-CMCertificate -Certificate $Cert -Verbose:$ReallyVerbose
    }
}

# Return the prompt to its original location
Set-Location $CD

# Output a reminder to manually renew the CMG cert if needed
Write-Host "Does the CMG certificate need to be updated?  This must be done manually!" -ForegroundColor Cyan

# Output completion
Write-Host "Processing complete" -ForegroundColor Green

# END SCRIPT BODY ------------------------------------------------
# STOP TRANSCRIPTING ---------------------------------------------
Stop-Transcript
# END SCRIPT -----------------------------------------------------
# SIGNATURE ------------------------------------------------------
