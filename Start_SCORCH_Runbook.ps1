<#

.SYNOPSIS
Author: Brian Gade (@Configur8rGator, www.configuratorgator.com)

.DESCRIPTION
Initiates a System Center Orchestrator Runbook using the information provided

.PARAMETER SCORCHServer
String.  The FQDN of the SCORCH server to communicate with.

.PARAMETER RunbookGUID
String.  The GUID of the runbook to initiate.

.PARAMETER ParameterHashtable
Hashtable.  The GUIDs and Values for the runbook's parameters.  
To have the script get data for a given value from a task sequence variable, enter TSV_ followed by the variable name as the value.
Format: @{"ParameterGUID1" = "ParameterValue1";"ParameterGUID2" = "TSV_TSVarName2"}

.PARAMETER WaitForCompletion
Switch.  Specify this switch to have the script wait for the runbook to complete, up to the MaxSecondsToWait time limit.

.PARAMETER MaxSecondsToWait
Integer.  Maximum number of seconds to wait for the runbook to complete.  Defaults to 300 seconds (five minutes).

.EXAMPLE
Start_SCORCH_Runbook.ps1 -SCORCHServer orchestrator.contoso.com -RunbookGUID "2a0e6dd7-fda4-4539-b765-1af96eed3dfa" -ParameterHashtable @{"e7e223ab-fe57-4705-8969-ec80115b7d73" = "This is the value for Param1.";"091fcc1e-d09a-4b95-b91b-d2600e59d444" = "TSV_TSVarName2"} -WaitForCompletion -MaxSecondsToWait 60

.NOTES
Change log:
v1.0.0, ConfiguratorGator, 7/2/19 - Original Version

--SQL QUERY TO FIND GUIDS
SELECT LOWER(POLICIES.UniqueID) AS 'Runbook GUID',
	CUSTOM_START_PARAMETERS.Value AS 'Parameter Name',
	LOWER(CUSTOM_START_PARAMETERS.UniqueID) AS 'Parameter GUID'
FROM POLICIES
INNER JOIN OBJECTS ON POLICIES.UniqueID = OBJECTS.ParentID
LEFT OUTER JOIN CUSTOM_START_PARAMETERS ON OBJECTS.UniqueID = CUSTOM_START_PARAMETERS.ParentID
WHERE POLICIES.Name = 'Add User to VPN Group' 
	AND policies.deleted = 0
	AND CUSTOM_START_PARAMETERS.Value IS NOT NULL
ORDER BY 'Parameter Name' ASC

.LINK
https://docs.microsoft.com/en-us/previous-versions/system-center/developer/hh921685(v=msdn.10)

.LINK
http://www.laurierhodes.info/?q=node/101

.LINK
https://stackoverflow.com/questions/25120703/invoke-webrequest-equivalent-in-powershell-v2

.LINK
https://my330space.wordpress.com/2017/07/03/how-to-run-orchestrator-runbook-using-powershell/

.LINK
https://codehollow.com/2016/02/invoke-webrequests-via-powershell/

#>
# DEFINE PARAMETERS ----------------------------------------------
Param(
    [Parameter(Mandatory=$True)]
        [string] $SCORCHServer,
    [Parameter(Mandatory=$True)]
        [string] $RunbookGUID,
    [Parameter(Mandatory=$True)]
        [hashtable] $ParameterHashtable,
    [Parameter(ParameterSetName='WaitForCompletion',Mandatory=$False)]
        [switch] $WaitForCompletion,
    [Parameter(ParameterSetName='WaitForCompletion',Mandatory=$False)]
		[int] $MaxSecondsToWait = 300
)
# END DEFINE PARAMETERS ------------------------------------------
# DEFINE VARIABLES -----------------------------------------------

$PowerShellVersion = $PSVersionTable.PSVersion.ToString()
$RunbookParametersString = ""
	
# END DEFINE VARIABLES -------------------------------------------
# SCRIPT BODY ----------------------------------------------------

# Create the TSEnv object and build the credential object
$TSEnv = New-Object -ComObject Microsoft.SMS.TSEnvironment
$Username = "domain\username"
$PasswordKey = [byte[]](<your number array here>)
$PasswordText = "<your encrypted password here>"
$Password = ConvertTo-SecureString -String $PasswordText -Key $PasswordKey
$Creds = New-Object System.Management.Automation.PSCredential($Username, $Password)

# Populate the data from the task sequence variables
# If the value provided starts with "tsv_", remove the prefix and treat the remaining text as a Task Sequence Variable name to get the data from
# Otherwise assume the value provided represents literal input and no action is needed
ForEach($Key in $ParameterHashtable.Keys.Split("`n"))
{
    If($ParameterHashtable[$Key].ToUpper() -like "TSV_*")
    {
        $TSVarName = $ParameterHashtable[$Key].Substring(4)
        $ParameterHashtable[$Key] = $TSEnv.Value($TSVarName)
    }
}

# Write out the runbook information so it shows in the log
Write-Host "Runbook GUID: $RunbookGUID"
Write-Host "Runbook Parameters: "
$ParameterHashtable | Format-Table -AutoSize
    
# Format the Runbook parameters, if any
If($Null -ne $ParameterHashtable)
{   
   # Format the param string from the Parameters hashtable
   $RunbookParametersString = "<d:Parameters><![CDATA[<Data>"
   ForEach($Parameter in $ParameterHashtable.GetEnumerator())
   {
      $RunbookParametersString = -join ($RunbookParametersString,"<Parameter><ID>{",$Parameter.Key,"}</ID><Value>",$Parameter.Value,"</Value></Parameter>")
   }
   $RunbookParametersString += "</Data>]]></d:Parameters>"
}
$RunbookParametersString

# Form the web request body
$WebRequestBody = @"
<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<entry xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices" xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata" xmlns="http://www.w3.org/2005/Atom">
    <content type="application/xml">
        <m:properties>
            <d:RunbookId m:type="Edm.Guid">$RunbookGUID</d:RunbookId>
            $RunbookParametersString
        </m:properties>
    </content>
</entry>
"@

# Submit the Web Request to Orchestrator
$SCORCH_URL = "http://$($SCORCHServer):81/Orchestrator2012/Orchestrator.svc/Jobs/"

$ResponseObject = Invoke-WebRequest -UseBasicParsing -Uri $SCORCH_URL -Method POST -Credential $Creds -Body $WebRequestBody -ContentType "application/atom+xml" 

# Retrieve the Job ID from the submitted request
$XML = [xml] $ResponseObject.Content
$RunbookJobURL = $XML.Entry.ID

# Get the runbook's current status
$Status = $XML.Entry.Content.Properties.Status
Write-Host "Runbook Status: $Status"

# If WaitForCompletion was specified, monitor the status until it completes or the time limit is reached
For($i = 0; $WaitForCompletion -eq $True -and $Status -ne "Completed" -and $i -lt $MaxSecondsToWait; $i++)
{ 
    Start-Sleep -Second 1

    # Query the web service for the current status
    $ResponseObject = Invoke-WebRequest -UseBasicParsing -Uri "$($RunbookJobURL)" -Method Get -Credential $Creds 
    $XML = [xml] $ResponseObject.Content
    $RunbookJobURL = $XML.Entry.ID
    $Status = $XML.Entry.Content.Properties.Status
    Write-Host "Runbook Status: $Status"
}

# If the time limit was reach, say so
If($i -eq $MaxSecondsToWait)
{
    Write-Host "WARNING: Timed out while waiting for runbook to complete.  Limit was $MaxSecondsToWait seconds."
}

# END SCRIPT BODY ------------------------------------------------
# END SCRIPT -----------------------------------------------------
# SIGNATURE ------------------------------------------------------
# SIG # Begin signature block
# MIIb0AYJKoZIhvcNAQcCoIIbwTCCG70CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUaqQctwkSkHiyOWIwK2nNIHba
# NPegghaJMIIEFDCCAvygAwIBAgILBAAAAAABL07hUtcwDQYJKoZIhvcNAQEFBQAw
# VzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNV
# BAsTB1Jvb3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw0xMTA0
# MTMxMDAwMDBaFw0yODAxMjgxMjAwMDBaMFIxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSgwJgYDVQQDEx9HbG9iYWxTaWduIFRpbWVzdGFt
# cGluZyBDQSAtIEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlO9l
# +LVXn6BTDTQG6wkft0cYasvwW+T/J6U00feJGr+esc0SQW5m1IGghYtkWkYvmaCN
# d7HivFzdItdqZ9C76Mp03otPDbBS5ZBb60cO8eefnAuQZT4XljBFcm05oRc2yrmg
# jBtPCBn2gTGtYRakYua0QJ7D/PuV9vu1LpWBmODvxevYAll4d/eq41JrUJEpxfz3
# zZNl0mBhIvIG+zLdFlH6Dv2KMPAXCae78wSuq5DnbN96qfTvxGInX2+ZbTh0qhGL
# 2t/HFEzphbLswn1KJo/nVrqm4M+SU4B09APsaLJgvIQgAIMboe60dAXBKY5i0Eex
# +vBTzBj5Ljv5cH60JQIDAQABo4HlMIHiMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMB
# Af8ECDAGAQH/AgEAMB0GA1UdDgQWBBRG2D7/3OO+/4Pm9IWbsN1q1hSpwTBHBgNV
# HSAEQDA+MDwGBFUdIAAwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFs
# c2lnbi5jb20vcmVwb3NpdG9yeS8wMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2Ny
# bC5nbG9iYWxzaWduLm5ldC9yb290LmNybDAfBgNVHSMEGDAWgBRge2YaRQ2XyolQ
# L30EzTSo//z9SzANBgkqhkiG9w0BAQUFAAOCAQEATl5WkB5GtNlJMfO7FzkoG8IW
# 3f1B3AkFBJtvsqKa1pkuQJkAVbXqP6UgdtOGNNQXzFU6x4Lu76i6vNgGnxVQ380W
# e1I6AtcZGv2v8Hhc4EvFGN86JB7arLipWAQCBzDbsBJe/jG+8ARI9PBw+DpeVoPP
# PfsNvPTF7ZedudTbpSeE4zibi6c1hkQgpDttpGoLoYP9KOva7yj2zIhd+wo7AKvg
# IeviLzVsD440RZfroveZMzV+y5qKu0VN5z+fwtmK+mWybsd+Zf/okuEsMaL3sCc2
# SI8mbzvuTXYfecPlf5Y1vC0OzAGwjn//UYCAp5LUs0RGZIyHTxZjBzFLY7Df8zCC
# BJ8wggOHoAMCAQICEhEh1pmnZJc+8fhCfukZzFNBFDANBgkqhkiG9w0BAQUFADBS
# MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEoMCYGA1UE
# AxMfR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBHMjAeFw0xNjA1MjQwMDAw
# MDBaFw0yNzA2MjQwMDAwMDBaMGAxCzAJBgNVBAYTAlNHMR8wHQYDVQQKExZHTU8g
# R2xvYmFsU2lnbiBQdGUgTHRkMTAwLgYDVQQDEydHbG9iYWxTaWduIFRTQSBmb3Ig
# TVMgQXV0aGVudGljb2RlIC0gRzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
# AoIBAQCwF66i07YEMFYeWA+x7VWk1lTL2PZzOuxdXqsl/Tal+oTDYUDFRrVZUjtC
# oi5fE2IQqVvmc9aSJbF9I+MGs4c6DkPw1wCJU6IRMVIobl1AcjzyCXenSZKX1GyQ
# oHan/bjcs53yB2AsT1iYAGvTFVTg+t3/gCxfGKaY/9Sr7KFFWbIub2Jd4NkZrItX
# nKgmK9kXpRDSRwgacCwzi39ogCq1oV1r3Y0CAikDqnw3u7spTj1Tk7Om+o/SWJMV
# TLktq4CjoyX7r/cIZLB6RA9cENdfYTeqTmvT0lMlnYJz+iz5crCpGTkqUPqp0Dw6
# yuhb7/VfUfT5CtmXNd5qheYjBEKvAgMBAAGjggFfMIIBWzAOBgNVHQ8BAf8EBAMC
# B4AwTAYDVR0gBEUwQzBBBgkrBgEEAaAyAR4wNDAyBggrBgEFBQcCARYmaHR0cHM6
# Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wCQYDVR0TBAIwADAWBgNV
# HSUBAf8EDDAKBggrBgEFBQcDCDBCBgNVHR8EOzA5MDegNaAzhjFodHRwOi8vY3Js
# Lmdsb2JhbHNpZ24uY29tL2dzL2dzdGltZXN0YW1waW5nZzIuY3JsMFQGCCsGAQUF
# BwEBBEgwRjBEBggrBgEFBQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNv
# bS9jYWNlcnQvZ3N0aW1lc3RhbXBpbmdnMi5jcnQwHQYDVR0OBBYEFNSihEo4Whh/
# uk8wUL2d1XqH1gn3MB8GA1UdIwQYMBaAFEbYPv/c477/g+b0hZuw3WrWFKnBMA0G
# CSqGSIb3DQEBBQUAA4IBAQCPqRqRbQSmNyAOg5beI9Nrbh9u3WQ9aCEitfhHNmmO
# 4aVFxySiIrcpCcxUWq7GvM1jjrM9UEjltMyuzZKNniiLE0oRqr2j79OyNvy0oXK/
# bZdjeYxEvHAvfvO83YJTqxr26/ocl7y2N5ykHDC8q7wtRzbfkiAD6HHGWPZ1BZo0
# 8AtZWoJENKqA5C+E9kddlsm2ysqdt6a65FDT1De4uiAO0NOSKlvEWbuhbds8zkSd
# wTgqreONvc0JdxoQvmcKAjZkiLmzGybu555gxEaovGEzbM9OuZy5avCfN/61PU+a
# 003/3iCOTpem/Z8JvE3KGHbJsE2FUPKA0h0G9VgEB7EYMIIGzzCCBLegAwIBAgIT
# SgAAABRXQOxmAPvP6gACAAAAFDANBgkqhkiG9w0BAQsFADBGMRMwEQYKCZImiZPy
# LGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYHcHJvbWVnYTEWMBQGA1UEAxMNUHJv
# bWVnYVJvb3RDQTAeFw0xNjA5MjAxOTI2MDhaFw0yODA5MjAxOTM2MDhaMFMxEzAR
# BgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdQUk9NRUdBMSMwIQYD
# VQQDExpQcm9tZWdhSXNzdWluZ0NBLU1BREFQUDBCQzCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBALKjCUE95EGJpQlWBzr8DNd/rdB6OTg9Tv4k11CMRCNF
# L50YBEzhaDSVulv//7iffHVF90TbrhQWnhepE1iqzUEeMmqaZm9sLEVYysGakVpj
# TF4HpYT0nkrhsPJwiOnWPazko8Zx0G6egXHKpXMS1+ww0G9IMZ51R9R6cY/tbPKZ
# JUmsvQit79zwXSi8b2OXBQqJQICq/bpqAG1L9B4IOkdMxWAuvaiuZX7t+0V5ucXv
# abi6a5x2X+1SaTUMxjAvDWnUXYQ7JKVdpUBwiT22nnMHQuSF0GwGQTFp9hG9MCJX
# by1LCG9pg2hWKD9XvL2WLWdAIsl82TL2KSb+glag080CAwEAAaOCAqcwggKjMBAG
# CSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBQS0JzMD61kIHzkElxXtV1oDk7K5TAZ
# BgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/
# BAUwAwEB/zAfBgNVHSMEGDAWgBRL8Ze8tdtgn92o7ydg1ocnxCAxFzCCAQYGA1Ud
# HwSB/jCB+zCB+KCB9aCB8oYwaHR0cDovL3BraS5wcm9tZWdhLmNvbS9wa2kvL1By
# b21lZ2FSb290Q0EoMikuY3JshoG9bGRhcDovLy9DTj1Qcm9tZWdhUm9vdENBKDIp
# LENOPVByb21lZ2FSb290Q0EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZp
# Y2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9cHJvbWVnYSxEQz1j
# b20/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNS
# TERpc3RyaWJ1dGlvblBvaW50MIIBCgYIKwYBBQUHAQEEgf0wgfowSQYIKwYBBQUH
# MAKGPWh0dHA6Ly9wa2kucHJvbWVnYS5jb20vcGtpL1Byb21lZ2FSb290Q0FfUHJv
# bWVnYVJvb3RDQSgyKS5jcnQwgawGCCsGAQUFBzAChoGfbGRhcDovLy9DTj1Qcm9t
# ZWdhUm9vdENBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1T
# ZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPXByb21lZ2EsREM9Y29tP2NBQ2Vy
# dGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5
# MA0GCSqGSIb3DQEBCwUAA4ICAQBbceEm6DTkY+kVBjCZ+NhIQdPj8Ocea1GCe7+9
# GT71bP9ntyRMEGGk6n8dJHrxgDU8kRYYXqj8WTKvXAJDYxwI/PABFHMIdLPc5TQ7
# QXDj7rrBPcYnvFOFv+fr7e6y0ngxE8evG5eYk8WRItprvDgEJx11KdvZQMO6ybZ4
# aAjuCQ/50obepNQle3DO+xMDhJfaiO0nb7MOg+Jr1eoMBq9oS9HHhN7QfVkOU4IC
# LWfZMM5F7qW+LdklETjeehSXV6Smhyi3KgylBH95C6BRq0lqUu5rYsrCdpL4oGuG
# 6BUhTJDfPQuiJBpUtF1BAict3ITootcHzsfjkwB+IMuGtp8Cmk1QtoSaOX/owlQg
# /yIlGISNXdwRnmMqg4OceYtwGfhIvy0+Q5BKR4XgsOt+aTMSK3zJGIlMtnoIO5t0
# oX4xJC0V6jwXPEjs9/GELtMM5931lPjfBXqZIRck+/BrS9Wgz/xIa57c0+Jgldzg
# tyq10IEySE3+LIntZMDHPI+W+ncps831cOx6zp5w12IehGdLdddtSNGn3w4Wvfzo
# DZ77xM+H06oWioinInZDxqPCnPaBMLJte6V8cakkj2kgFBrXuLGe65Qi5V5WhuOW
# MFUFz7AVLIzcA+zIXvXAIhJhCmDcdbze60Xe6oMMBLo5gzmBeG3+eANnmzOGYmXm
# o1PEpTCCBvcwggXfoAMCAQICEyQAAFyx6hJO6r19MB4AAAAAXLEwDQYJKoZIhvcN
# AQELBQAwUzETMBEGCgmSJomT8ixkARkWA2NvbTEXMBUGCgmSJomT8ixkARkWB1BS
# T01FR0ExIzAhBgNVBAMTGlByb21lZ2FJc3N1aW5nQ0EtTUFEQVBQMEJDMB4XDTE4
# MDgyOTE3NDcwOFoXDTIxMDgyODE3NDcwOFowfzELMAkGA1UEBhMCVVMxEjAQBgNV
# BAgTCVdpc2NvbnNpbjEQMA4GA1UEBxMHTWFkaXNvbjEcMBoGA1UEChMTUHJvbWVn
# YSBDb3Jwb3JhdGlvbjEQMA4GA1UECxMHSW5mb1NlYzEaMBgGA1UEAxMRaXRnc3Mu
# cHJvbWVnYS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCfGDzs
# hcSkjCvRUQJNnSdHuXcJohM1XZd50XTQWP5oif3dkjiA+uyzsEj2aCEHkvQRIRS2
# DQfkVoZpxY+4k4aDIsMH80kau7Vlvz/XehJLjRWCQo6rIVnEOctp2ao6SqoKxPuq
# 0C7StvGoRCOw3zlnO5aTvkm5+Fwq92rPNfIU6HWW7cN6mEfGZmdB1bU6AGcFmgBU
# ZkO3DWDGlrVAUlYzynhy+q6ALYon3kVRCQHHAAs5zmJJSZy8FMVmGMRw+Ajifa3V
# XxbhVBnpExqaS/dzSZc5vfzFUO2Ee+74ALFX0ogCbmgFCELvwd52hZ6GyjCrTghW
# un91H+WH78W5pTPdAgMBAAGjggOWMIIDkjALBgNVHQ8EBAMCB4AwEwYDVR0lBAww
# CgYIKwYBBQUHAwMweAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgICAIAwDgYI
# KoZIhvcNAwQCAgCAMAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJYIZIAWUD
# BAECMAsGCWCGSAFlAwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNVHQ4EFgQU
# SIucJXxDGia7b5nPlG0TpIpB3A0wHwYDVR0jBBgwFoAUEtCczA+tZCB85BJcV7Vd
# aA5OyuUwggEhBgNVHR8EggEYMIIBFDCCARCgggEMoIIBCIaBw2xkYXA6Ly8vQ049
# UHJvbWVnYUlzc3VpbmdDQS1NQURBUFAwQkMsQ049TUFEQVBQMENCLENOPUNEUCxD
# Tj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1
# cmF0aW9uLERDPVBST01FR0EsREM9Y29tP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxp
# c3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludIZAaHR0cDov
# L3BraS5wcm9tZWdhLmNvbS9DZXJ0RW5yb2xsL1Byb21lZ2FJc3N1aW5nQ0EtTUFE
# QVBQMEJDLmNybDCCATIGCCsGAQUFBwEBBIIBJDCCASAwgbkGCCsGAQUFBzAChoGs
# bGRhcDovLy9DTj1Qcm9tZWdhSXNzdWluZ0NBLU1BREFQUDBCQyxDTj1BSUEsQ049
# UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJh
# dGlvbixEQz1QUk9NRUdBLERDPWNvbT9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0
# Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTBiBggrBgEFBQcwAoZWaHR0cDov
# L3BraS5wcm9tZWdhLmNvbS9DZXJ0RW5yb2xsL01BREFQUDBDQi5wcm9tZWdhLmNv
# bV9Qcm9tZWdhSXNzdWluZ0NBLU1BREFQUDBCQy5jcnQwPAYJKwYBBAGCNxUHBC8w
# LQYlKwYBBAGCNxUIgYDSRIaGhRaHyYkOh9CnWqvpAS2Hz4tIh+f3NAIBZAIBGDAb
# BgkrBgEEAYI3FQoEDjAMMAoGCCsGAQUFBwMDMA0GCSqGSIb3DQEBCwUAA4IBAQAq
# yiUQ7n+ZGIjiZrnKVKUzR4i+0ptFaGzjGR4VWVtY2Q31RW7JbF7mGNHnK9Ikae3K
# BbimXEuTVV4lN6L2nSepc+I2/YiY+NazAVxm0zs5yH2smhikqlsUqg74ZWhaLrMz
# EkSVGRuRK2atOCQ+RRG0oRbeAbiLbnUIX4Jck8yqSXXUR56k7yI5fzvxw4Wl3K9K
# kg+/lpFpHnz6Qd/uA+oJZaMKSdpn81QRC19ELTzgF89SRDstVlLvjVhw/XmMrMCb
# 8LTuRtSxejipZ63qI+Ek32qZfdfU+AmJjva2bK6lAG9nYzZkFxMHifPesx0wOVk9
# GLdESSPj+tkMrjm3mNFVMYIEsTCCBK0CAQEwajBTMRMwEQYKCZImiZPyLGQBGRYD
# Y29tMRcwFQYKCZImiZPyLGQBGRYHUFJPTUVHQTEjMCEGA1UEAxMaUHJvbWVnYUlz
# c3VpbmdDQS1NQURBUFAwQkMCEyQAAFyx6hJO6r19MB4AAAAAXLEwCQYFKw4DAhoF
# AKB4MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisG
# AQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcN
# AQkEMRYEFNWAVf85vp21aTkD7+vCSxOXX/PeMA0GCSqGSIb3DQEBAQUABIIBABVq
# QpKEfRlRUZk1Ii+AMIb1+P/apNJLZcGmRxDBSBJ2hOyPFF0majPXpn54QXbn59qi
# 0UIlX+FY5MP9u1HrQtwc4ISJ2OK9/7KBTebR0AQBlWIA1yNavTfUCrUljxpx+D87
# q6rzdwgnbnIp8njrSVSF1b2X5Qm5Dzoj+KPxn/IN8Tgcbix90Qd5ZnMd4qVsm/t5
# fEb/PgPXg6YjsnV1/Q/IApjWk14+D2bfOo56brQgUHjuI0nri9ErJYVFPmlcpnEF
# i7+/0fXKXCwI+AXpAH6tFZNIAKoUP8Y1ReyapSx8833GlKAyqRtr4mC8y8UxMm+I
# IzPFMTDdjb4/VM++GuihggKiMIICngYJKoZIhvcNAQkGMYICjzCCAosCAQEwaDBS
# MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEoMCYGA1UE
# AxMfR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBHMgISESHWmadklz7x+EJ+
# 6RnMU0EUMAkGBSsOAwIaBQCggf0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAc
# BgkqhkiG9w0BCQUxDxcNMTkxMjIwMTMxNDQ1WjAjBgkqhkiG9w0BCQQxFgQU9i9U
# 6E4RDkS7H96nQKDK+l/JImUwgZ0GCyqGSIb3DQEJEAIMMYGNMIGKMIGHMIGEBBRj
# uC+rYfWDkJaVBQsAJJxQKTPseTBsMFakVDBSMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTEoMCYGA1UEAxMfR2xvYmFsU2lnbiBUaW1lc3Rh
# bXBpbmcgQ0EgLSBHMgISESHWmadklz7x+EJ+6RnMU0EUMA0GCSqGSIb3DQEBAQUA
# BIIBADE+rKvuzZBKOH3cXiBzbC74tSw99aYonWPnt6XSe9aGQSR6lIKzI3VfUlNy
# dJ+BTPeVaLMcqDD39aOzGFLR40QpebkPbMhJaXFrCZmZa43LoW6yjyriGlAJ7S4U
# 0aQDAokaG+otMxap24s0TkyJRbeln6BWjQXgcfUAJU798qSSmkWe7gcDn/7MgsOs
# OwpIUE78x5pn6CjQLKG49c4c0mvjUokH7RxPPQMjINu35HxdTKfdkl965GHHUJQC
# PJRHsjxBz0XLycXypTcp/VADrWKK22Qp1LXDUuCArRNHJIenneK3aTotmkRdCh1L
# TuYj/npZqfSfPKB22w/orNlOdV8=
# SIG # End signature block
