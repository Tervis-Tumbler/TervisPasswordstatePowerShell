#Requires -Modules SecureStringFile
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
