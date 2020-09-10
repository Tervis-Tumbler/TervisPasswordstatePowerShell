$ModulePath = if ($PSScriptRoot) {
	$PSScriptRoot
} else {
	(Get-Module -ListAvailable TervisPasswordstatePowerShell).ModuleBase
}

$TervisPasswordstateCustomProperties = [PSCustomObject]@{
    Name = "OracleDatabase"
    PropertyMap = @{    
        Host = "GenericField1"
        Port = "GenericField2"
        Service_Name = "GenericField3"
    }
},
[PSCustomObject]@{
    Name = "SybaseDatabase"
    PropertyMap = @{    
        Host = "GenericField1"
        Port = "GenericField2"
        ServerName = "GenericField3"
        DatabaseName = "GenericField4"        
    }
},
[PSCustomObject]@{
    Name = "MSSQLDatabase"
    PropertyMap = @{    
        Server = "GenericField1"
        Port = "GenericField2"
        Database = "GenericField4"
    }
    ForEachProcessScriptBlock = {
        $_ | Add-Member -MemberType ScriptProperty -Name Credential -Value {
            New-Crednetial -Username $This.UserName -Password $This.Password
        }
    }
}

function Get-TervisPasswordstateCustomProperties {
    param (
        $Name
    )
    $TervisPasswordstateCustomProperties |
    Where-Object {-not $Name -or $_.Name -eq $Name}
}

function Get-TervisPasswordstatePassword {
    [CmdletBinding(DefaultParameterSetName="NonPropertyMapName")]
    param (
        [Parameter(Mandatory)]$Guid,

        [ValidateScript({
            $_ -in (Get-TervisPasswordstateCustomProperties | Select-Object -ExpandProperty Name)
        })]
        [Parameter(ParameterSetName = "PropertyMapName")]$PropertyMapName,
        [Parameter(ParameterSetName = "NonPropertyMapName")][Switch]$AsCredential,
        [Switch]$StoreInCache
    )
    $CachedPasswordCliXmlPath = @"
$ModulePath\..\TervisPasswordstatePasswordCache\$(
    $PSBoundParameters |
    ConvertFrom-PSBoundParameters -ExcludeProperty StoreInCache |
    ConvertTo-Hash -HashFunction MD5
).xml
"@
    $UseCachedPassword = if ($env:UseTervisPasswordstatePasswordCache) {
        Test-Path -Path $CachedPasswordCliXmlPath
    }

    if (-not $UseCachedPassword) {
        $Password = Find-PasswordstatePassword -GenericField10 $Guid -AsCredential:$AsCredential |
        Select-Object -First 1

        if ($PropertyMapName) {
            $Password |
            Add-TervisPasswordStateCustomProperty -PropertyMapName $PropertyMapName
        }
    
        if ($StoreInCache) {
            $FileInfo = [System.IO.FileInfo]$CachedPasswordCliXmlPath
            
            New-Item -ItemType Directory -Force -ErrorAction SilentlyContinue -Path $FileInfo.DirectoryName | Out-Null

            $Password |
            Export-Clixml -Path $CachedPasswordCliXmlPath
        }

        $Password
    } elseif ($UseCachedPassword) {
        $CachedPasswordCliXmlPath |
        Import-Clixml
    }
}

function Add-TervisPasswordStateCustomProperty {
    param (
        [Parameter(Mandatory,ValueFromPipeline)]$Password,
        $PropertyMapName
    )
    process {
        $TervisPasswordstateCustomProperty = Get-TervisPasswordstateCustomProperties -Name $PropertyMapName
        $TervisPasswordstateCustomProperty.PropertyMap.GetEnumerator() |
        ForEach-Object {
            $Password | Add-Member -MemberType AliasProperty -Name $_.Name -Value $_.Value
        }
        $Password | ForEach-Object -Process $TervisPasswordstateCustomProperty.ForEachProcessScriptBlock    
    }
}

function New-TervisPasswordstatePasswordGUID {
    param (
        $PasswordID
    )
    $Guid = New-Guid | Select-Object -ExpandProperty GUID
    $ExistingGUid = Get-PasswordstatePassword -ID $PasswordID | Select-Object -ExpandProperty GenericField10
    if ($ExistingGUid) { 
        $ExistingGUid
    } else {
        Set-PasswordstatePassword -PasswordID $PasswordID -GenericField10 $Guid
    }
}

function Get-PasswordstateOracleDatabaseEntryDetails {
    param (
        [Parameter(Mandatory)][Alias("PasswordID")]$ID
    )
    $PasswordstateEntryDetails = Get-PasswordstatePassword -ID $ID
    
    $PasswordstateEntryDetails |
    Add-Member -MemberType AliasProperty -Name Host -Value GenericField1 -PassThru |
    Add-Member -MemberType AliasProperty -Name Port -Value GenericField2 -PassThru |
    Add-Member -MemberType AliasProperty -Name Service_Name -Value GenericField3 -PassThru |
    Select UserName, Password, Host, Port, Service_Name
}

function Get-PasswordstateOracleDatabasePassword {
    param (
        [Parameter(Mandatory)]$ID
    )
    $Password = Get-PasswordstatePassword -ID $ID
    
    $Password |
    Add-Member -MemberType AliasProperty -Name Host -Value GenericField1 -PassThru |
    Add-Member -MemberType AliasProperty -Name Port -Value GenericField2 -PassThru |
    Add-Member -MemberType AliasProperty -Name Service_Name -Value GenericField3 -PassThru |
    Select UserName, Password, Host, Port, Service_Name
}

function Get-PasswordstateSybaseDatabaseEntryDetails {
    param (
        [Parameter(Mandatory)]$GUID
    )
    $PasswordstateEntryDetails = Get-TervisPasswordstatePassword -Guid $GUID
    
    $PasswordstateEntryDetails |
    Add-Member -MemberType AliasProperty -Name Host -Value GenericField1 -PassThru |
    Add-Member -MemberType AliasProperty -Name Port -Value GenericField2 -PassThru |
    Add-Member -MemberType AliasProperty -Name ServerName -Value GenericField3 -PassThru |
    Add-Member -MemberType AliasProperty -Name DatabaseName -Value GenericField4 -PassThru |
    Select UserName, Password, Host, Port, ServerName, DatabaseName
}


function Get-PasswordstateMSSQLDatabaseEntryDetails {
    param (
        [Parameter(Mandatory)][Alias("PasswordID")]$ID
    )
    $PasswordstateEntryDetails = Get-PasswordstatePassword -ID $ID
    
    $PasswordstateEntryDetails |
    Add-Member -MemberType AliasProperty -Name Server -Value GenericField1 -PassThru |
    Add-Member -MemberType AliasProperty -Name Port -Value GenericField2 -PassThru |
    Add-Member -MemberType AliasProperty -Name Database -Value GenericField4 -PassThru |
    Add-Member -MemberType ScriptProperty -Name Credential -Value {
        New-Crednetial -Username $This.UserName -Password $This.Password
    } -PassThru |
    Select UserName, Password, Server, Port, Database, Credential
}

function Get-PasswordstateDirectAccessDetails {
    param (
        [Parameter(Mandatory)][Alias("PasswordID")]$ID
    )
    $PasswordstateEntryDetails = Get-PasswordstatePassword -ID $ID
    
    $PasswordstateEntryDetails |
    Add-Member -MemberType AliasProperty -Name NrptExclusionList -Value GenericField1 -PassThru |
    Select NrptExclusionList
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
        $ScheduledTaskCredential = Get-PasswordstatePassword -AsCredential -ID 259
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

function Get-TervisPasswordStateApplicationPasswordTitle {
    param (
        [Parameter(Mandatory)][ValidateSet("LocalAdministrator")]$Type,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ApplicationName,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$EnvironmentName       
    )
    process {
        "$ApplicationName Application Node Local Administrator $EnvironmentName"
    }
}

function New-TervisPasswordStateApplicationPassword {
    param (
        [Parameter(Mandatory)][ValidateSet("LocalAdministrator")]$Type,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ApplicationName,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$EnvironmentName
    )
    process {
        if ($Type -eq "LocalAdministrator") {
            $PasswordTitle = Get-TervisPasswordStateApplicationPasswordTitle @PSBoundParameters
            $Password = Find-PasswordstatePassword -Title $PasswordTitle -ErrorAction SilentlyContinue
            if (-not $Password) {
                $PasswordList = Find-PasswordstateList -PasswordList "Windows Server Applications Administrator"
                New-PasswordstatePassword -GeneratePassword $true -PasswordListID $PasswordList.PasswordListID -Title $PasswordTitle -UserName ".\administrator"
            } else {
                $Password
            }
        }
    }
}

function Get-TervisPasswordStateApplicationPassword {
    param (
        [Parameter(Mandatory)][ValidateSet("LocalAdministrator")]$Type,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ApplicationName,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$EnvironmentName,
        [Switch]$AsCredential
    )
    process {
        if ($Type -eq "LocalAdministrator") {
            $PSBoundParameters.Remove("AsCredential") | Out-Null
            $PasswordTitle = Get-TervisPasswordStateApplicationPasswordTitle @PSBoundParameters
            Find-PasswordstatePassword -Title $PasswordTitle -ErrorAction SilentlyContinue -AsCredential:$AsCredential
        }    
    }
}

function Get-TervisPasswordSateTervisDotComWildCardCertificate {
    param (
        [ValidateSet("pfx","crt","key")]$Type,
        $OutPath
    )
    #Document IDs from the password under the \Infrastructure\Windows Server Applications Administrator password list
    #Document IDs are not consistent accross password lists, only use non application specific password list password document IDs
    $TypeToDocumentIDMapping = @{
        pfx = 83 # 2020 wildcard cert pfx
        crt = 85 # 2020 wildcard cert crt
        key = 84 # 2020 wildcard cert key
    }

    Get-PasswordstateDocument -DocumentID $TypeToDocumentIDMapping.$Type -OutFile "$OutPath\certificate.$Type" -DocumentLocation password
}
function Get-TervisPasswordSateTervisDotComWildCardCertificatePassword {
    param (
        [Switch]$AsString
    )
    $Password = Get-TervisPasswordstatePassword -Guid "02dae3ad-8f21-427f-8a35-b940797da51e" | # 2020 wildcard cert GUID
    Select-Object -ExpandProperty Password
    if (-not $AsString) {
        $Password |
        ConvertTo-SecureString -AsPlainText -Force
    } else {
        $Password
    }
}

function Enter-TervisSSHSession {
    param (
        $ComputerName
    )
    Find-PasswordstatePassword -Search "nexus"
}