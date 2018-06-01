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
    if ($env:PasswordStatePowerShellPasswordStateAPIKey) {
        $env:PasswordStatePowerShellPasswordStateAPIKey
    } else {
        Get-SecureStringFile -InputFile $(Get-PasswordStateAPIKeyPath)
    }
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
    $CoreParameters = if ($PSVersionTable.PSEdition -ne "Core") {@{}} else {@{SkipCertificateCheck = $true}}
    Invoke-RestMethod $URLToPasswordstateCredential @CoreParameters
}

function Get-PasswordstateCredential {
    param (
        [string]$PasswordstateListAPIKey = $(Get-PasswordStateAPIKey),
        [Parameter(Mandatory)][string]$PasswordID,
        [switch] $AsPlainText
    )

    $URLToPasswordstateCredential = "https://passwordstate/api/passwords/$PasswordID`?apikey=$PasswordstateListAPIKey"
    $CoreParameters = if ($PSVersionTable.PSEdition -ne "Core") {@{}} else {@{SkipCertificateCheck = $true}}
    $PasswordstateCredentials = Invoke-RestMethod $URLToPasswordstateCredential @CoreParameters

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

Function Get-PasswordstateDocument {
    param (
        [Parameter(Mandatory)][string]$DocumentID,
        [Parameter(Mandatory)][string]$FilePath,
        [string]$PasswordstateListAPIKey = $(Get-PasswordStateAPIKey)
    )
    $URLToPasswordstateCredential = "https://passwordstate/api/document/password/$DocumentID`?apikey=$PasswordstateListAPIKey"
    Invoke-RestMethod $URLToPasswordstateCredential -OutFile $FilePath
}

function Invoke-PasswordstateProvision {
    param (
        $EnvironmentName
    )
    $ApplicationName = "Passwordstate"
    Invoke-ApplicationProvision -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName
    $Nodes | Update-TervisSNMPConfiguration
    Get-ADGroup Privilege_InfrastructurePasswordstateAdministrator | Add-ADGroupMember -Members Scheduledtasks
    $Nodes | Install-PasswordstateServicerestartScheduledTask
}

function Install-PasswordstateServicerestartScheduledTask {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $ScheduledTaskCredential = New-Object System.Management.Automation.PSCredential (Get-PasswordstateCredential -PasswordID 259)
        $Execute = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        $ScheduledTaskName = "PasswordstateServiceRestart"
    }
    process {
        $Argument = "-NoProfile -Command Invoke-Command -ComputerName $Computername -ScriptBlock {Restart-Service -Name 'Passwordstate Service' -Force}"
        $CimSession = New-CimSession -ComputerName $ComputerName
        If (Get-ScheduledTask -TaskName $ScheduledTaskName -CimSession $CimSession -ErrorAction SilentlyContinue) {
            Uninstall-TervisScheduledTask -TaskName $ScheduledTaskName -ComputerName Scheduledtasks -Force
        }
        Install-TervisScheduledTask -Credential $ScheduledTaskCredential -TaskName $ScheduledTaskName -Execute $Execute -Argument $Argument -RepetitionIntervalName Every12HoursEveryDay -ComputerName Scheduledtasks

#        If (-NOT (Get-ScheduledTask -TaskName PushExplorerFavorites -CimSession $CimSession -ErrorAction SilentlyContinue)) {
#            Install-TervisScheduledTask -Credential $ScheduledTaskCredential -TaskName PushExplorerFavorites -Execute $Execute -Argument $Argument -RepetitionIntervalName EverWorkdayDuringTheDayEvery15Minutes -ComputerName $ComputerName
#        }
    }
}