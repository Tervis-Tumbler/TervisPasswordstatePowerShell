#Requires -Modules SecureStringFile, TervisVirtualization

Function Install-PasswordStatePowerShell {
    Set-PasswordStateAPIKey
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
    param (
        [Parameter(Mandatory)]$PasswordStateAPIKey
    )    
    New-SecureStringFile -OutputFile $env:USERPROFILE\PasswordState.APIKey -SecureString $($PasswordStateAPIKey | ConvertTo-SecureString -AsPlainText -Force)
    Set-PasswordStateAPIKeyPath -PasswordStateAPIKeyPath $env:USERPROFILE\PasswordState.APIKey
}

Function Get-PasswordStateAPIKey {
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

#Requires -Modules SecureStringFile
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

function New-PasswordstateADSecurityGroup {
    Param(
        [Parameter(Mandatory)]
        [ValidateSet(“Delta”,”Epsilon”,"Production")]
        $Environment,
        
        [Parameter(Mandatory)]
        [ValidateScript({ Test-ShouldBeAlphaNumeric $PasswordstateListName $_ })]
        $PasswordstateFolderName,
        
        [Parameter(Mandatory)]
        [ValidateScript({ Test-ShouldBeAlphaNumeric $PasswordstateListName $_ })]
        $PasswordstateListName
    )
    $OUToCreateSecurityGroup = "OU=Passwordstate Privileges,OU=Company - Security Groups,DC=tervis,DC=prv"
    
    if($Environment -eq "Production"){
        $EnvironmentName = "Prod"
    }    
    else{
        $EnvironmentName = $Environment
    }
        $PasswordstateSecurityGroupName = "Privilege`_Passwordstate`_$EnvironmentName`_$PasswordstateFolderName`_$PasswordstateListName"
        New-ADGroup -GroupCategory:'Security' -GroupScope:'Universal' -Name:$PasswordstateSecurityGroupName -Path:$OUToCreateSecurityGroup -SamAccountName:$PasswordstateSecurityGroupName
    
    $PasswordstateSecurityGroupName
}

$TervisPasswordstateEnvironments = [pscustomobject][ordered]@{
    Name="Delta"
    FolderID = "58"
    TemplatePasswordListID = "2"
},
[pscustomobject][ordered]@{
    Name = "Epsilon"
    FolderID = "56"
    TemplatePasswordListID = "2"
},
[pscustomobject][ordered]@{
    Name = "Production"
    FolderID = "59"
    TemplatePasswordListID = "2"
}

function Get-TervisPasswordstateEnvironments {
    param(
        [Parameter(Mandatory)][ValidateSet(“Delta”,”Epsilon”,"Production")][String]$EnvironmentName
    )
    $TervisPasswordstateEnvironmentSelection = $TervisPasswordstateEnvironments | Where name -EQ $EnvironmentName
    $TervisPasswordstateEnvironmentSelection
}

function New-PasswordstateApplicationFolder{
    param(
        [Parameter(Mandatory)]
        [ValidateSet(“Delta”,”Epsilon”,"Production")]
        $PasswordstateEnvironment,

        [Parameter(Mandatory)]
        [string]
        $FolderNameToCreate,
        
        [Parameter(Mandatory)]
        [string]
        $FolderDescription
    )
    $PasswordstateEnvironmentInformation = Get-TervisPasswordstateEnvironments -EnvironmentName $PasswordstateEnvironment

    $SystemWideAPIKey = Get-SecureStringFile -InputFile "\\fs1\disasterrecovery\Source Controlled Items\SecuredCredential API Keys\PasswordstateSiteWideAPIKey.APIKEY"
    
    $CreatedPasswordstateApplicationFolder = New-PasswordstateFolder -ParentFolderIDtoNestUnder $PasswordstateEnvironmentInformation.FolderID -FolderNameToCreate $FolderNameToCreate -FolderDescription $FolderDescription -SystemWideAPIKey $SystemWideAPIKey
    $CreatedPasswordstateApplicationFolder
}

Function New-PasswordstateApplicationList{
    param(
        [Parameter(Mandatory)]
        [ValidateSet(“Delta”,”Epsilon”,"Production")]
        $PasswordstateEnvironment,

        [Parameter(Mandatory)]
        [string]
        $ApplicationListNametoCreate,
        
        [Parameter(Mandatory)]
        [string]
        $ApplicationListDescription,

        [Parameter(Mandatory)]
        $ParentFolderIDtoNestUnder
    )
    $PasswordstateEnvironmentInformation = Get-TervisPasswordstateEnvironments -EnvironmentName $PasswordstateEnvironment
    $SystemWideAPIKey = Get-SecureStringFile -InputFile "\\fs1\disasterrecovery\Source Controlled Items\SecuredCredential API Keys\PasswordstateSiteWideAPIKey.APIKEY"
    $CreatedPasswordstateApplicationList = New-PasswordstateSharedList -SharedListNametoCreate $ApplicationListNametoCreate -SharedListDescription $ApplicationListDescription -ParentFolderIDtoNestUnder $ParentFolderIDtoNestUnder -TemplatePasswordListID $PasswordstateEnvironmentInformation.TemplatePasswordListID -SystemWideAPIKey $SystemWideAPIKey
    $CreatedPasswordstateApplicationList
}


function New-PasswordstateFolder {
    param(
        [Parameter(Mandatory)][string]$ParentFolderIDtoNestUnder,
        [Parameter(Mandatory)][string]$FolderNameToCreate,
        [Parameter(Mandatory)][string]$FolderDescription,
        [Parameter(Mandatory)][string]$SystemWideAPIKey
    )
$jsontocreateFolder = @"
{
 "FolderName":"$FolderNameToCreate",
 "Description":"$FolderDescription",
 "CopyPermissionsFromPasswordListID":"",
 "CopyPermissionsFromTemplateID":"",
 "NestUnderFolderID":"$ParentFolderIDtoNestUnder",
 "APIKey":"$SystemWideAPIKey"
}
"@
    $result = Invoke-Restmethod -Method Post -Uri https://passwordstate/api/folders -ContentType "application/json" -Body $jsontocreateFolder
    $CreatedFolderID = $result.FolderID
    $CreatedFolderID
}

Function New-PasswordstateSharedList {
    param(
        [Parameter(Mandatory)][string]$SharedListNametoCreate,
        [Parameter(Mandatory)][string]$SharedListDescription,
        [Parameter(Mandatory)][string]$ParentFolderIDtoNestUnder,
        [Parameter(Mandatory)][string]$TemplatePasswordListID,
        [Parameter(Mandatory)][string]$SystemWideAPIKey
    )
    
$jsontoCreatePasswordList = @"
{
"PasswordList":"$SharedListNametoCreate",
"Description":"$SharedListDescription",
"CopySettingsFromPasswordListID":"",
"CopySettingsFromTemplateID":"$TemplatePasswordListID",
"LinkToTemplate":false,
"CopyPermissionsFromPasswordListID":"",
"CopyPermissionsFromTemplateID":"$TemplatePasswordListID",
"NestUnderFolderID":"$ParentFolderIDtoNestUnder",
"APIKey":"$SystemWideAPIKey"
}
"@
    $result = Invoke-Restmethod -Method Post -Uri https://passwordstate/api/passwordlists -ContentType "application/json" -Body $jsontoCreatePasswordList
    $PasswordListID = $result.PasswordListID
    $PasswordListID

}