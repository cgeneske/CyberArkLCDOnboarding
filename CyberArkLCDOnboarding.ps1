<#
.SYNOPSIS
Onboards an account to the CyberArk Vault via PVWA API, primarily designed for use with EPM LCD and as part of an endpoint imaging process

.DESCRIPTION
This script onboards an account stub (with no password) to the CyberArk Vault via PVWA API and queues it for an immediate 
password change via CPM.  It leverages CCP to securely retrieve a PVWA API credential for the automation activity, and supports CCP 
OS User (IWA/NEGOTIATE) authentication [RECOMMENDED].  

This script is primarily designed to be invoked through an endpoint imaging workflow (i.e. Microsoft SCCM Task Sequence) with 
intent to lifecycle manage the local administrator accounts on endpoints that will receive an EPM agent (i.e. Loosely Connected Devices), 
but can also be run interactively and in other circumstances.  Another example might be for domain-joined endpoints, where the
onboarding platform is configured with a reconcile account and ChangePasswordInResetMode = Yes.

Local admin privileges are not required to execute this script.

CyberArk least-privileges that are required for the PVWA API user...

On safe(s) that are targeted for onboarding:

    - List Accounts (for detecting duplicates)
    - Add Accounts
    - Update Account Properties
    - Update Account Content (only if an existing object would need to be undeleted as a part of the onboarding motion)
    - Initiate CPM account management operations

For existing account detection to avoid inadvertently onboarding duplicates:

    - Membership in the "Auditors" group

    or

    - List Accounts (in all safes that may possibly contain a duplicate)

In the Global Variables region, you MUST set values to the variables within the CHANGE-ME section that are relevant 
for your organization.  The CHANGE-ME variables are as follows:

$CyberArkAPIObjectName   - The object name (e.g. "account name") of the CyberArk Vaulted password object for your PVWA API user
$CyberArkAPIObjectSafe   - The CyberArk Safe that your PVWA API password object resides within
$CyberArkPVWAHostname    - The CyberArk Password Vault Web Access (PVWA) Hostname
$CyberArkCCPHostname     - The CyberArk Central Credential Provider (CCP) Hostname
$CyberArkCCPPort         - The CyberArk CCP Port Number
$CyberarkCCPServiceRoot  - The CyberArk CCP IIS Application (i.e. default is "AIMWebService") you wish to connect to
$CyberarkCCPAppId        - The Application ID you are identifying as to the CyberArk CCP platform
$CyberArkDefaultSafe     - The default CyberArk Safe for onboarding. This safe will be used if no target safe is provided, the target safe 
                           doesn't exist, or permission is denied for the API user.
$CyberArkCCPAuthOSUser   - Set $true [RECOMMENDED] to use OS User authentication (IWA/NEGOTIATE) to CyberArk CCP otherwise, set $false
$IgnoreSSLCertErrors     - Set $true to ignore SSL Certificate Errors (i.e. CN/SAN mismatch, and self-signed errors) otherwise, set $false [RECOMMENDED]

.EXAMPLE
CyberArkLCDOnboarding.ps1 -TargetUserName "Administrator" `
                          -TargetAddress "winclient.cybr.com" `
                          -TargetPlatform "WinLooselyDevice" `
                          -TargetSafe "EPM-Onboarding"

.INPUTS
TargetUserName          - The UserName of the account being onboarded
TargetAddress           - The FQDN/IP address of the endpoint that the account being onboarded resides
TargetPlatform          - The CyberArk Platform under which to onboard the account
TargetSafe              - The CyberArk Safe to onboard the account into

.OUTPUTS
None

.NOTES
AUTHOR:
Craig Geneske

VERSION HISTORY:
1.0 3/8/2023 - Initial Release

DISCLAIMER:
This solution is provided as-is - it is not supported by CyberArk nor an official CyberArk solution.
#>

################################################### SCRIPT PARAMETERS ###################################################
#region Script Parameters

Param(
    [Parameter(Mandatory = $true)]
    [string]$TargetUserName,
    
    [Parameter(Mandatory = $true)]
    [string]$TargetAddress,

    [Parameter(Mandatory = $true)]
    [string]$TargetPlatform,

    [Parameter(Mandatory = $false)]
    [string]$TargetSafe
)

#endregion

################################################### GLOBAL VARIABLES ####################################################
#region Global Variables

### BEGIN CHANGE-ME SECTION ###

$CyberArkAPIObjectName = "epmlcd.pass"
$CyberArkAPIObjectSafe = "EPM API User"
$CyberArkPVWAHostname = "pam.cybr.com"
$CyberArkCCPHostname = "ccp.cybr.com"     
$CyberArkCCPPort = 443
$CyberarkCCPServiceRoot = "AIMWebServiceIWA" 
$CyberarkCCPAppId = "EPM LCD Onboarding"
$CyberArkDefaultSafe = "EPM LCD Staging"
$CyberArkCCPAuthOSUser = $true
$IgnoreSSLCertErrors = $false

### END CHANGE-ME SECTION ###

$ExecGUID = [guid]::NewGuid()
$PVWABaseURI = "https://$CyberArkPVWAHostname/PasswordVault/api"
$PVWAAuthLogonUrl = $PVWABaseURI + "/auth/CyberArk/Logon"
$PVWAAuthLogoffUrl = $PVWABaseURI + "/auth/Logoff"
$PVWAAccountsUrl = $PVWABaseURI + "/Accounts"
$CCPGetCredentialUrl = "https://$($CyberArkCCPHostname):$CyberArkCCPPort/$CyberArkCCPServiceRoot/api/Accounts?" + `
                        "Safe=$([System.Web.HttpUtility]::UrlEncode($CyberArkAPIObjectSafe))" + `
                        "&Object=$([System.Web.HttpUtility]::UrlEncode($CyberArkAPIObjectName))" + `
                        "&AppId=$([System.Web.HttpUtility]::UrlEncode($CyberArkCCPAppId))"

#endregion

#################################################### LOADING TYPES ######################################################
#region Loading Types

#Used for URL safe encoding within System.Web.HttpUtility
Add-Type -AssemblyName System.Web -ErrorAction Stop 

#Used for ignoring SSL Certificate errors if so specified in global variables - Technique to remain compatible with PowerShell version 5 and below
if (!("CACertValidation" -as [type]) -and $IgnoreSSLCertErrors) {
    Add-Type -TypeDefinition @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class CACertValidation {
    public static bool IgnoreSSLErrors(object sender,
        X509Certificate certificate,
        X509Chain chain,
        SslPolicyErrors sslPolicyErrors) { return true; }

    public static RemoteCertificateValidationCallback GetDelegate() {
        return new RemoteCertificateValidationCallback(CACertValidation.IgnoreSSLErrors);
    }
}
"@
}

#endregion

################################################# FUNCTION DECLARATIONS #################################################
#region Funciton Declarations

Function WriteLog {
    <#
    .SYNOPSIS
        Writes a consistently formatted log entry to stdout and/or an optional log file
    .DESCRIPTION
        This function is designed to provide a way to consistently format log entries and extend them to
        one or more desired outputs (i.e. stdout and/or a log file).  Each log entry consists of three main
        sections:  Date/Time, Event Type, and the Event Message.  This function is also extended to output
        a standard header during script invocation and footer at script conclusion.
    .PARAMETER Type
        Sets the type of event message to be output.  This must be a member of the defined ValidateSet:
        INF [Informational], WRN [Warning], ERR [Error].
    .PARAMETER Message
        An optional message to prepend to the error output, providing useful context to the raw response
    .EXAMPLE
        [FUNCTION CALL]     : WriteLog -Type INF -Message "Account was onboarded successfully"
        [FUNCTION RESULT]   : 02/09/2023 09:43:25 | [INF] | Account was onboarded successfully
    .NOTES
        Author: Craig Geneske
    #>
    Param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('INF','WRN','ERR')]
        [string]$Type,

        [Parameter(Mandatory = $false)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [switch]$Header,

        [Parameter(Mandatory = $false)]
        [switch]$Footer
    )

    $eventColor = [System.Console]::ForegroundColor
    if ($Header) {
        if ([Environment]::UserInteractive) {
            $eventString = @"
###############################################################################################################################
#                                                                                                                             #
#                                            CyberArk EPM-LCD | Onboarding Utility                                            #
#                                                                                                                             #
###############################################################################################################################
"@
        }
        else {
            $eventString = ""
        }

        $eventString += "`n`n-----------------------> BEGINNING SCRIPT [$ExecGUID] @ $(Get-Date -Format "MM/dd/yyyy HH:mm:ss") <-----------------------`n"
        $eventColor = "Cyan"
    }
    elseif ($Footer) {
        $eventString = "`n------------------------> ENDING SCRIPT [$ExecGUID] @ $(Get-Date -Format "MM/dd/yyyy HH:mm:ss") <------------------------`n"
        $eventColor = "Cyan"
    }
    else {
        $eventString =  $(Get-Date -Format "MM/dd/yyyy HH:mm:ss") + " | [$Type] | $ExecGUID | " + $Message
        switch ($Type){
            "WRN" { $eventColor = "Yellow"; Break }
            "ERR" { $eventColor = "Red"; Break }
        }
    }

    Write-Host $eventString -ForegroundColor $eventColor

    #TODO - Implement optional [simultaneous] log file output?
}

Function ParseFailureResult {
    <#
    .SYNOPSIS
        Parses the ErrorRecord from a Failed REST API call to present more user-friendly feedback
    .DESCRIPTION
        PVWA and CCP components will return a number of situationally common response codes and error codes.
        The goal of this function is to provide a means of parsing those responses, in order to deliver more
        consistent, formatted, and meaningful feedback to stdout and/or a log file.
    .PARAMETER Component
        The CyberArk component that is supplying the response failure.  This must be a member of the defined
        ValidateSet: PVWA, CCP
    .PARAMETER Message
        An optional message to prepend to the error output, providing useful context to the raw response
    .EXAMPLE
        ParseFailureResult -Component PVWA -Message "A failure occurred while searching for existing accounts"
    .NOTES
        Author: Craig Geneske
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('CCP','PVWA')]
        [string]$Component,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    switch ($Component){
        "CCP" { 
            #TODO - Expand for more human-readable presentation of common/unique 404,403,401 error scenarios at CCP?
            $ErrorText = $null
            if (!$ErrorRecord.ErrorDetails){
                $ErrorText = $ErrorRecord.Exception.Message
                if ($ErrorRecord.Exception.InnerException) {
                    $ErrorText += " --> " + $ErrorRecord.Exception.InnerException.Message
                }
            }
            else{
                $ErrorText = $ErrorRecord.ErrorDetails
            }
            WriteLog -Type ERR -Message $($Message + " --> " + $ErrorText)
            Break
        }
        "PVWA" {
            #TODO - Expand for more human-readable presentation of common/unique 404,403,401 error scenarios at PVWA?
            $ErrorText = $null
            if (!$ErrorRecord.ErrorDetails){
                $ErrorText = $ErrorRecord.Exception.Message
                if ($ErrorRecord.Exception.InnerException) {
                    $ErrorText += " --> " + $ErrorRecord.Exception.InnerException.Message
                }
            }
            else{
                $ErrorText = $ErrorRecord.ErrorDetails
            }
            WriteLog -Type ERR -Message $($Message + " --> " + $ErrorText)
            Break
         }
    }
}

Function RetrieveAPICredential {
    <#
    .SYNOPSIS
        Retrieves a CyberArk PVWA API credential from CyberArk CCP
    .DESCRIPTION
        Retrieves a CyberArk PVWA API credential from CyberArk CCP.  The $CCPGetCredentialUrl is constructed in the global
        variable declaration section of the script, using various input parameters that describe the CCP endpoint and
        API credential to be retrieved.  Additionally, if the script-level -CyberArkCCPAuthOSUser switch is specified,
        then IWA authentication (NEGOTIATE) will be attempted against the CCP web service.  Otherwise, no extra authentication
        is attempted against CCP (and you generally rely upon "Allowed Machines" authentication).  If the attempt is successful,
        the credential response JSON (serialized into a PSObject by Invoke-RestMethod) is returned.  If the attempt fails, an 
        exception is thrown.
    .EXAMPLE
        $pvwaCred = RetrieveAPICredential
    .NOTES
        Author: Craig Geneske

        The following script-level input parameters and globals are used:
            - $CCPGetCredentialUrl
            - $CyberArkCCPAuthOSUser
    #>
    $result = $null
    $methodArgs = @{
        Method = "Get"
        Uri = $CCPGetCredentialUrl
        ContentType = "application/json"
    }

    if ($CyberArkCCPAuthOSUser){
       $methodArgs.Add("UseDefaultCredentials", $true)
    }

    WriteLog -Type INF -Message "Attempting to retrieve the PVWA API credential from CCP..."
    try {

        $result = Invoke-RestMethod @methodArgs
    } 
    catch {
        ParseFailureResult -Component CCP -ErrorRecord $_ -Message "Failed to retrieve PVWA API credential from CCP"
        throw
    }
    WriteLog -Type INF -Message "Successfully retrieved PVWA API credential from CCP"
    return $result
}

Function AuthenticateToPVWA {
    <#
    .SYNOPSIS
        Authenticates to the CyberArk PVWA API
    .DESCRIPTION
        Authenticates to the CyberArk PVWA API via the CyberArk authentication method, with concurrency set true
        to support parallel script executions.  If authentication succeeds, the session token is returned.  If
        authentication fails, an exception is thrown.
    .EXAMPLE
        $PVWASessionToken = AuthenticateToPVWA
    .NOTES
        The following script-level input parameters and globals are used: 
            - $PVWAAuthLogonUrl
        
        Author: Craig Geneske
    #>
    $pvwaCred = RetrieveAPICredential

    $postBody = @{
        username = $pvwaCred.Username
        password = $pvwaCred.Content
        concurrentSession = $true 
    } | ConvertTo-Json
    
    WriteLog -Type INF -Message "Attempting to authenticate to PVWA API..."
    try {
        $result = Invoke-RestMethod -Method Post -Uri $PVWAAuthLogonUrl -Body $postBody -ContentType "application/json"
    }
    catch {
        ParseFailureResult -Component PVWA -ErrorRecord $_ -Message "Failed to authenticate to PVWA API"
        $pvwaCred = $null
        $postBody = $null
        throw
    } 
    WriteLog -Type INF -Message "Successfully authenticated to PVWA API"
    $pvwaCred = $null
    $postBody = $null
    return $result
}

Function CheckIfAccountExists {
    <#
    .SYNOPSIS
        Checks to see if an account already exists in the CyberArk Vault via API
    .DESCRIPTION
        Checks for the existence of a matching account in the CyberArk Vault via API.
        If an existing account is found with a matching username and address, an exception is thrown.
    .PARAMETER SessionToken
        Session token that was received from the PVWA Logon endpoint
    .EXAMPLE
        CheckIfAccountExists -SessionToken "YmNlODFhZjktNjdkMS00Yzg3LThiMDctMTAxOGMzNzU3ZWJkOzFFNj...."
    .NOTES
        The following script-level input parameters and globals are used: 
            - $PVWAAccountsUrl
            - $TargetUserName
            - $TargetAddress

        Author: Craig Geneske
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [string]$SessionToken
    )

    $finalUrl = $PVWAAccountsUrl + "?search=$([System.Web.HttpUtility]::UrlEncode($TargetUserName)) $([System.Web.HttpUtility]::UrlEncode($TargetAddress))"

    WriteLog -Type INF -Message "Attempting to check if account [$TargetUsername@$TargetAddress] already exists in the Vault..."
    try {
        $results = Invoke-RestMethod -Method Get -Uri $finalUrl -Headers @{ Authorization = $SessionToken } -ContentType "application/json"
    }
    catch {
        ParseFailureResult -Component PVWA -ErrorRecord $_ -Message "Failed to get accounts via PVWA API, unable to check for [$TargetUsername@$TargetAddress]"
        throw
    }
    
    if ($results.count -gt 0) {
        foreach ($acct in $results.value) {
            if ($acct.userName -match "^$([Regex]::Escape($TargetUsername))$" -and $acct.address -match "^$([Regex]::Escape($TargetAddress))$") {
                WriteLog -Type WRN -Message "Success, account [$TargetUsername@$TargetAddress] already exists, skipping any further onboarding action"
                throw
            }
        }
    }
    WriteLog -Type INF -Message "Success, account [$TargetUsername@$TargetAddress] does not exist, proceeding with onboarding action"
}

Function OnBoardAccountToVault {
    <#
    .SYNOPSIS
        Onboards an account to the CyberArk Vault via API
    .DESCRIPTION
        Onboards an account to the CyberArk Vault via the CyberArk PVWA API.  This function will also 
        queue the newly onboarded account for immediate CPM rotation, which will be actioned by the 
        EPM Agent on that endpoint upon next check-in interval.  If onboarding fails, an exception is thrown.
    .PARAMETER SessionToken
        Session token that was received from the PVWA Logon endpoint
    .EXAMPLE
        OnBoardAccountToVault -SessionToken "YmNlODFhZjktNjdkMS00Yzg3LThiMDctMTAxOGMzNzU3ZWJkOzFFNj...."
    .NOTES
        The following script-level input parameters and globals are used:
            - $PVWAAccountsUrl
            - $TargetUserName
            - $TargetAddress
            - $TargetPlatform
            - $TargetSafe
            - $CyberArkDefaultSafe

        Author: Craig Geneske
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [string]$SessionToken
    )

    $finalSafe = ""

    if ($TargetSafe) {
        $finalSafe = $TargetSafe
    }
    else {
        $finalSafe = $CyberArkDefaultSafe
    }

    $postBody = @{
        userName = $TargetUserName
        address = $TargetAddress
        platformId = $TargetPlatform
        safeName = $finalSafe
    } | ConvertTo-Json

    WriteLog -Type INF -Message "Attempting to onboard account [$TargetUserName@$TargetAddress] to Target Safe [$finalSafe]"
    try {
        $result = Invoke-RestMethod -Method Post -Uri $PVWAAccountsUrl -Body $postBody -Headers @{ Authorization = $SessionToken } -ContentType "application/json"
        WriteLog -Type INF -Message "Successfully onboarded the account [$TargetUserName@$TargetAddress] to Target Safe [$finalSafe] - AccountId [$($result.Id)]"
    }
    catch {
        ParseFailureResult -Component PVWA -ErrorRecord $_ -Message "Failed to onboard the account [$TargetUserName@$TargetAddress] to Target Safe [$finalSafe]"
        #PASWS031E - Safe Doesn't Exist
        #ITATS955E - Permission Denied
        #In either of these cases, we should attempt to onboard into the Default Safe defined in Global Variables, if it wasn't yet attempted
        if (($_.ErrorDetails.Message -match "PASWS031E" -or $_.ErrorDetails.Message -match "ITATS955E") -and $finalSafe -ne $CyberArkDefaultSafe) {
            WriteLog -Type INF -Message "Attempting to onboard account [$TargetUserName@$TargetAddress] to Default Safe [$CyberArkDefaultSafe]"
            $postBody = @{
                userName = $TargetUserName
                address = $TargetAddress
                platformId = $TargetPlatform
                safeName = $CyberArkDefaultSafe
            } | ConvertTo-Json
            try {
                $result = Invoke-RestMethod -Method Post -Uri $PVWAAccountsUrl -Body $postBody -Headers @{ Authorization = $SessionToken } -ContentType "application/json"
                WriteLog -Type INF `
                         -Message "Successfully onboarded the account [$TargetUserName@$TargetAddress] to Default Safe [$CyberArkDefaultSafe] - AccountId [$($result.Id)]"
                $Error.Clear()
            }
            catch {
                ParseFailureResult -Component PVWA `
                                   -ErrorRecord $_ `
                                   -Message "Failed to onboard the account [$TargetUserName@$TargetAddress] to Default Safe [$CyberArkDefaultSafe]"
                throw
            }
        }
        else {
            throw
        } 
    }

    WriteLog -Type INF -Message "Attempting to queue an immediate password change via CPM..."
    try {
        Invoke-RestMethod -Method Post -Uri $($PVWAAccountsUrl + "/$($result.Id)/Change") -Headers @{ Authorization = $SessionToken } -ContentType "application/json" *> $null
        WriteLog -Type INF -Message "Success, account should be picked up for change at the next EPM Agent evaluation cycle"
    }
    catch {
        ParseFailureResult -Component PVWA -ErrorRecord $_ -Message "Failed to queue the account for an immediate change"
        throw
    }
}

Function LogoffPVWA {
    <#
    .SYNOPSIS
        Executes logoff from the CyberArk PVWA API
    .DESCRIPTION
        Logoff from the CyberArk PVWA API, removing the Vault session.  This as an explicit step is 
        important for immediately freeing the session, when API concurrency is in effect
    .PARAMETER SessionToken
        Session token that was received from the PVWA Logon endpoint
    .EXAMPLE
        LogoffPVWA -SessionToken "YmNlODFhZjktNjdkMS00Yzg3LThiMDctMTAxOGMzNzU3ZWJkOzFFNj...."
    .NOTES
        The following script-level input parameters and globals are used:
            - $PVWAAuthLogoffUrl

        Author: Craig Geneske
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [string]$SessionToken
    )
    try {
        WriteLog -Type INF -Message "Attempting to logoff PVWA API..."
        Invoke-RestMethod -Method Post -Uri $PVWAAuthLogoffUrl -Headers @{ Authorization = $SessionToken} *> $null
        WriteLog -Type INF -Message "PVWA API logoff was successful"
    } 
    catch {
        WriteLog -Type WRN -Message "Unable to logoff of PVWA API - $($_.Exception.Message)"
    }
}

Function Main{
    <#
    .SYNOPSIS
        Main entry point for the script
    .DESCRIPTION
        Contains core logic and execution flow for the script
    .EXAMPLE
        Main
    .NOTES
        AUTHOR: Craig Geneske
    #>

    $PVWASessionToken = $null
    $Error.Clear()

    #Print Log/Console Header
    WriteLog -Header

    if ($IgnoreSSLCertErrors) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [CACertValidation]::GetDelegate()
        WriteLog -Type WRN -Message "You have disabled SSL Certificate validation, this setting is NOT recommended!"
    }
    else {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    }

    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

    try {
        $PVWASessionToken = AuthenticateToPVWA
        CheckIfAccountExists -SessionToken $PVWASessionToken
        OnBoardAccountToVault -SessionToken $PVWASessionToken
    } 
    catch {
        #Nothing to do but maintaining catch block to suppress error output as this is processed and formatted further down in the call stack
    } 
    finally {
        if ($Error.Count) {
            WriteLog -Type WRN -Message "Script execution is being interrupted, aborting"
        }
        else {
            WriteLog -Type INF -Message "All actions have completed successfully"
        }
        if ($PVWASessionToken) {
            LogoffPVWA -SessionToken $PVWASessionToken
            $PVWASessionToken = $null
        }
    }

    #Print Log/Console Footer
    WriteLog -Footer
}

#endregion

################################################### SCRIPT ENTRY POINT ##################################################
Main