#Requires -Modules SecureStringFile
#Requires -Modules TervisVirtualization

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