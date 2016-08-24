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
    $APIKeyURI = Get-SecuredStringFromFile -InputFile $SecuredAPIkeyFilePath
    $PasswordstateCredentialObject = Invoke-RestMethod $APIKeyURI
    
    $PasswordstateCredentialObject
}
