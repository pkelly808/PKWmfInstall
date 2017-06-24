#Find-Module xPendingReboot -RequiredVersion 0.1.0.2
#Find-Module xWindowsUpdate -RequiredVersion 1.0

$Global:WMFUncPath = '\\LVDSC01\Share\'

$Global:WMFScriptPath = Split-Path $Script:MyInvocation.MyCommand.Path
$Global:WMFConfig = 'PKWmfInstall'


#region Private Functions

Configuration $Global:WMFConfig {
    Import-DscResource -Module PSDesiredStateConfiguration, xWindowsUpdate, xPendingReboot

    Node $ComputerName {

        LocalConfigurationManager {
            RebootNodeIfNeeded = $Reboot
            RefreshMode        = 'PUSH'
        }

        File TempDir {
            DestinationPath = 'C:\Temp'
            Force           = $True
            Ensure          = 'Present'
            Type            = 'Directory'
        }

        File WMFSource {
            DestinationPath = "C:\Temp\$File"
            Ensure          = 'Present'
            SourcePath      = Join-Path $Global:WMFUncPath $File
            Type            = 'File'
            Force           = $True
            DependsOn       = '[File]TempDir'
        }

        if (!($CopyOnly)) {
            xHotFix WMFInstall {
                Id        = $KB
                Ensure    = 'Present'
                Path      = "C:\Temp\$File"
                DependsOn = '[File]WMFSource'
            }

            if ($Reboot) {
                xPendingReboot WMFReboot {
                    Name      = 'RebootMe'
                    DependsOn = '[xHotFix]WMFInstall'
                }
            }
        }
    }
}

function Copy-PKResource {

[CmdletBinding()]
param(
    [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [string[]]$ComputerName,

    [string[]]$Module
)

    PROCESS {

        foreach ($Computer in $ComputerName) {

            foreach ($Mod in $Module) {

                if (!(Get-Module $Mod -ListAvailable)) {
                    try {
                        Install-Module $Mod -Force
                    } catch {
                        Write-Warning "Unable to install $Mod"
                        continue
                    }
                }

                Copy-Item "$Env:ProgramFiles\WindowsPowerShell\Modules\$Mod" "\\$ComputerName\C$\Program Files\WindowsPowerShell\Modules\" -Recurse -Force
            }
        }
    }
}

function New-PKWmfConfiguration {

[CmdletBinding()]
param(
    [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [string[]]$ComputerName,

    [bool]$Reboot,
    [bool]$CopyOnly,

    [string]$File = 'Win8.1AndW2K12R2-KB3191564-x64.msu'
)

    BEGIN {
        if (!(Test-Path (Join-Path $Global:WMFUncPath $File))) {
            Write-Warning "File not found $(Join-Path $Global:WMFUncPath $File)"
            break
        }

        $KB = $File.Split('-') | Where-Object {$_ -match 'KB'}
        Write-Verbose $KB

        $Working = (Get-Location).Path
        Set-Location $Global:WMFScriptPath
    }

    PROCESS {

        foreach ($Computer in $ComputerName) {

            #Set-NetFirewallRule -CimSession $Computer -DisplayGroup "File and Printer Sharing" -Profile Domain -Enabled True

            #Copy-PKResource -ComputerName $Computer -Module xWindowsUpdate,xPendingReboot

            Invoke-Expression "$Global:WMFConfig"
        }
    }

    END {
        Set-Location $Working
    }
}

#endregion


function New-PKWmfShare {

[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
param(
    [string]$FolderPath = 'C:\',
    [string]$FolderName = 'Share'
)

    BEGIN {
        if (!($Global:WMFUncPath -eq "\\$env:COMPUTERNAME\$FolderName\")) {
            Write-Warning "Does not match Global UNC Path: $Global:WMFUncPath"
            break
        }

        if (Test-Path $Global:WMFUncPath) {
            Write-Warning "$Global:WMFUncPath already exists"
            break
        }

        $FullPath = Join-Path $FolderPath $FolderName
    }

    PROCESS {

        if ($PSCmdlet.ShouldProcess("Create Share $Global:WMFUncPath")) {

            if (!(Test-Path $FullPath)) {
                New-Item -Path $FolderPath -Name $FolderName -Type Directory | Out-Null
                Write-Host "Created $FullPath"
            }

            New-SmbShare -ReadAccess Everyone -Path $FullPath -Name $FolderName | Out-Null
            Write-Host "Shared $Global:WMFUncPath"
        }

        if ($PSCmdlet.ShouldProcess('Download WMF')) {

            #$OperatingSystem = 'W2K8R2','W2K12','W2K12R2'
            $OperatingSystem = 'W2K12R2'

            $ConfirmationPage = 'http://www.microsoft.com/en-us/download/' + $((Invoke-WebRequest 'http://aka.ms/wmf5latest' -UseBasicParsing).Links | ? Class -eq 'mscom-link download-button dl' | % href)

            foreach ($OS in $OperatingSystem) {
                $URL = ((Invoke-WebRequest $ConfirmationPage -UseBasicParsing).Links | ? Class -eq 'mscom-link' | ? href -match $OS).href[0]
                Write-Verbose "$URL"
                
                Invoke-WebRequest $URL -OutFile (Join-Path $FullPath $($URL.Split('/')[-1]))
            }      
        }
    }
}


function Start-PKWmfInstall {

[CmdletBinding()]
param(
    [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [string[]]$ComputerName,
    [bool]$Reboot = $false,
    [bool]$CopyOnly = $false
)

    PROCESS {

        $Path = Join-Path $Global:WMFScriptPath $Global:WMFConfig
        Write-Verbose $Path

        foreach ($Computer in $ComputerName) {

            if (!(Test-Path "$Path" -Include "$Computer*")) {
                $Files = New-PKWmfConfiguration -ComputerName $Computer -Reboot $Reboot -CopyOnly $false
                $Files | ForEach-Object { Write-Verbose "Created $_" }
            }

            #Set-NetFirewallRule -CimSession $Computer -DisplayGroup "File and Printer Sharing" -Profile Domain -Enabled True

            Copy-PKResource -ComputerName $Computer -Module xWindowsUpdate,xPendingReboot

            Set-DscLocalConfigurationManager -Path "$Path" -Verbose

            Start-DscConfiguration -Path "$Path" -ComputerName $Computer -Wait -Verbose -Force
        }
    }
}


function Get-PKWmfInstall {

[CmdletBinding()]
param(
    [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [string[]]$ComputerName
)

    PROCESS {

        foreach ($Computer in $ComputerName) {

            if (!(Test-WSMan $Computer -ea SilentlyContinue)) {
                Write-Warning "Connection denied $Computer"
                continue
            }

            $Version = Invoke-Command -ComputerName $Computer -ScriptBlock { "$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)" }

            try {
                Get-DscConfiguration -CimSession $Computer -ea Stop | Out-Null
                $Clear = $false
            } catch {
                $Clear = $true
            }

            [PSCustomObject]@{
                ComputerName=$Computer
                PowerShell=$Version
                ConfigRemoved=$Clear
            }
        }
    }
}

function Clear-PKWmfConfiguration {
    $Path = Join-Path $Global:WMFScriptPath $Global:WMFConfig

    try {
        Remove-Item "$Path" -Recurse -Force -ea Stop
    } catch {
        Write-Warning "Nothing to clear in $Path"
    }
}

function Remove-PKWmfConfiguration {

[CmdletBinding()]
param(
    [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [string[]]$ComputerName
)

    PROCESS {

        foreach ($Computer in $ComputerName) {

            Invoke-Command -ComputerName $Computer -ScriptBlock {
                Remove-Item 'C:\windows\system32\configuration\*.mof'
                Remove-Item 'C:\Program Files\WindowsPowerShell\Modules\[xc]*' -Recurse -Force
            }
        }

        Get-PKWmfInstall -ComputerName $Computer
    }
}
