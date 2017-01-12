#Requires -Modules SecureStringFile

Function Install-PasswordStatePowerShell {
    if(-not (Get-PasswordStateAPIKey) ) {
        Set-PasswordStateAPIKey
    }
}

Function Set-PasswordStateAPIKeyPath {
    Param (
        [Parameter(Mandatory)]$PasswordStateAPIKeyPath
    )
    [Environment]::SetEnvironmentVariable( "PasswordStatePowerShellPasswordStateAPIKeyPath", $PasswordStateAPIKeyPath, "User" )
}

Function Get-PasswordStateAPIKeyPath {
    if ($env:PasswordStatePowerShellPasswordStateAPIKeyPath) {
        $env:PasswordStatePowerShellPasswordStateAPIKeyPath
    } else {
        Throw "Set-PasswordStateAPIKey has not been run yet or PowerShell needs to be closed and reopened to see that the `$env:PasswordStatePowerShellPasswordStateAPIKeyPath has a value"
    }
}

Function Set-PasswordStateAPIKey {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]$PasswordStateAPIKey
    )    
    New-SecureStringFile -OutputFile $env:USERPROFILE\PasswordState.APIKey -SecureString $($PasswordStateAPIKey | ConvertTo-SecureString -AsPlainText -Force)
    Set-PasswordStateAPIKeyPath -PasswordStateAPIKeyPath $env:USERPROFILE\PasswordState.APIKey
}

Function Get-PasswordStateAPIKey {
    [CmdletBinding()]
    param ()
    Get-SecureStringFile -InputFile $(Get-PasswordStateAPIKeyPath)
}

function Get-PasswordStateCredentialFromFile {
    <#
    .SYNOPSIS
     Uses Passwordstate APIKey stored securely using New-SecuredStringToFile and Get-SecuredStringFromFile to output stored credentials from Passwordstate.
    .DESCRIPTION
     
    .EXAMPLE
    Get-PasswordstateCredentialFromFile
    .PARAMETER InputFile
    Fully qualified path to input file
    #>
    
    param(
        [Parameter(Mandatory)]
        [string]$SecuredAPIkeyFilePath
    )
    $APIKeyURI = Get-SecureStringFile -InputFile $SecuredAPIkeyFilePath
    $PasswordstateCredentialObject = Invoke-RestMethod $APIKeyURI
    
    $PasswordstateCredentialObject
}

function New-PasswordStateCredentialToFile {
    <#
    .SYNOPSIS
     Secure stores Passwordstate APIKey and password using New-SecureStringFile and Get-SecureStringFile to be used in scripts.
    .DESCRIPTION
     
    .EXAMPLE
    Set-PasswordstateCredentialToFile
    .PARAMETER APIKey
    APIKey for Password list
    .PARAMETER PasswordID
    PasswordID for credential within Passwordstate
    #>
    
    param(
        [Parameter(Mandatory)]
        [string]$DestinationSecureFile,
        [Parameter(Mandatory)]
        [string]$APIKey,
        [Parameter(Mandatory)]
        [string]$PasswordID
    )
    
    $URLToPasswordstateCredential = "https://passwordstate/api/passwords/$PasswordID`?apikey=$APIKEY"
    $SecureString = ConvertTo-SecureString -String $URLToPasswordstateCredential -AsPlainText -Force
    New-SecureStringFile -OutputFile $DestinationSecureFile -SecureString $SecureString
}

Function Get-PasswordstateEntryDetails {
    param (
        [Parameter(Mandatory)][string]$PasswordID,
        [string]$PasswordstateListAPIKey = $(Get-PasswordStateAPIKey)
    )
    $URLToPasswordstateCredential = "https://passwordstate/api/passwords/$PasswordID`?apikey=$PasswordstateListAPIKey"
    Invoke-RestMethod $URLToPasswordstateCredential
}

function Get-PasswordstateCredential {
    param (
        [string]$PasswordstateListAPIKey = $(Get-PasswordStateAPIKey),
        [Parameter(Mandatory)][string]$PasswordID,
        [switch] $AsPlainText
    )

    $URLToPasswordstateCredential = "https://passwordstate/api/passwords/$PasswordID`?apikey=$PasswordstateListAPIKey"
    $PasswordstateCredentials = Invoke-RestMethod $URLToPasswordstateCredential

    if ($AsPlainText){
        $PasswordstateCredentialObject = [pscustomobject][ordered]@{
            Username = $PasswordstateCredentials.Username
            Password = $PasswordstateCredentials.Password
            }
    }
    else {
    $PasswordstateCredentialsPassword = ConvertTo-SecureString $PasswordstateCredentials.Password -AsPlainText -Force
    $PasswordstateCredentialObject = New-Object System.Management.Automation.PSCredential ($PasswordstateCredentials.UserName, $PasswordstateCredentialsPassword)
    }

    return $PasswordstateCredentialObject
}

function New-PasswordstateEntry {
    param(
        [Parameter(Mandatory)][string]$PasswordListID,
        [Parameter(Mandatory)][string]$Username,
        [Parameter(Mandatory)][string]$Title,
        [string]$PasswordstateListAPIKey = $(Get-PasswordStateAPIKey)
    )

    $jsonString = @"
    {
        "PasswordListID":"$PasswordListID",
        "Title":"$Title",
        "UserName":"$Username",
        "APIKey":"$PasswordstateListAPIKey",
        "GeneratePassword":"true"
    }
"@
    Invoke-Restmethod -Method Post -Uri https://passwordstate/api/passwords/ -ContentType "application/json" -Body $jsonString -Verbose


}