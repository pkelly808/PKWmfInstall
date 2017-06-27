#region Private Functions

Configuration PKWmfInstall {
    Import-DscResource -Module PSDesiredStateConfiguration,@{ModuleName='xWindowsUpdate';ModuleVersion='1.0'},@{ModuleName='xPendingReboot';ModuleVersion='0.1.0.2'}

    Node $ComputerName {

        LocalConfigurationManager {
            RebootNodeIfNeeded = $Reboot
            RefreshMode        = 'PUSH'
        }

        File TempDir {
            DestinationPath = 'c:\temp'
            Force           = $True
            Ensure          = 'Present'
            Type            = 'Directory'
        }

        File WMFSource {
            DestinationPath = "c:\temp\$File"
            Ensure          = 'Present'
            SourcePath      = $FullPath
            Type            = 'File'
            Force           = $True
            DependsOn       = '[File]TempDir'
        }

        if (!($CopyOnly)) {
            xHotFix WMFInstall {
                Id        = $KB
                Ensure    = 'Present'
                Path      = "c:\temp\$File"
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

            if ($Computer -ne $env:COMPUTERNAME -and $Computer -ne 'localhost' -and $Computer -ne '.') {

                foreach ($Mod in $Module) {

                    Copy-Item "$Env:ProgramFiles\WindowsPowerShell\Modules\$Mod" "\\$Computer\C$\Program Files\WindowsPowerShell\Modules\" -Recurse -Force

                }
            }
        }
    }
}

function New-PKWmfConfiguration {

[CmdletBinding(SupportsShouldProcess,ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [string[]]$ComputerName,

    [bool]$Reboot,
    [bool]$CopyOnly
)

    BEGIN {
        $Config = Get-Content (Join-Path (Split-Path $Script:MyInvocation.MyCommand.Path) 'config.json') | ConvertFrom-Json
        $FullPath = Join-Path $Config.WMFUncPath $Config.W2K12R2
        $File = $Config.W2K12R2

        if (!(Test-Path $FullPath)) {
            Write-Warning "File not found $FullPath"
            break
        }

        $KB = $File.Split('-') | Where-Object {$_ -match 'KB'}
        Write-Verbose $KB

        $Working = (Get-Location).Path
        Set-Location (Split-Path $Script:MyInvocation.MyCommand.Path)
    }

    PROCESS {

        foreach ($Computer in $ComputerName) {

            if ($PSCmdlet.ShouldProcess($Computer)) {

                PKWmfInstall
            
            }
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

    PROCESS {

        $WMFUncPath = "\\$env:COMPUTERNAME\$FolderName\"
        $Path = Join-Path $FolderPath $FolderName

        if (!(Test-Path $WMFUncPath)) {

            if ($PSCmdlet.ShouldProcess($WMFUncPath)) {

                if (!(Test-Path $Path)) {
                    New-Item -Path $FolderPath -Name $FolderName -Type Directory | Out-Null
                    Write-Verbose "Created $Path"
                }

                New-SmbShare -ReadAccess Everyone -Path $Path -Name $FolderName | Out-Null
                Write-Verbose "Shared $WMFUncPath"
            }
        }

        $Config = New-Object PSObject
        $Config | Add-Member -NotePropertyName WMFUncPath -NotePropertyValue $WMFUncPath


        #$OperatingSystem = 'W2K8R2','W2K12','W2K12R2'
        $OperatingSystem = 'W2K12R2'

        $ConfirmationPage = 'http://www.microsoft.com/en-us/download/' + $((Invoke-WebRequest 'http://aka.ms/wmf5latest' -UseBasicParsing).Links | Where-Object Class -eq 'mscom-link download-button dl' | ForEach-Object {$_.href})

        foreach ($OS in $OperatingSystem) {
            $URL = ((Invoke-WebRequest $ConfirmationPage -UseBasicParsing).Links | Where-Object Class -eq 'mscom-link' | Where-Object href -match $OS).href[0]
            Write-Verbose "Url $URL"

            $File = $URL.Split('/')[-1]

            Invoke-WebRequest $URL -OutFile (Join-Path $Path $File)
            Write-Verbose "Downloaded $File"

            $Config | Add-Member -NotePropertyName $OS -NotePropertyValue $File
        }

        $Config | ConvertTo-Json | Out-File (Join-Path (Split-Path $Script:MyInvocation.MyCommand.Path) 'config.json')
    }
}


function Start-PKWmfInstall {

[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
param(
    [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [string[]]$ComputerName,

    [bool]$Reboot = $false,
    [bool]$CopyOnly = $false
)

    BEGIN {
        if (!(Test-Path (Join-Path (Split-Path $Script:MyInvocation.MyCommand.Path) 'config.json'))) {
            Write-Warning 'Please run New-PKWmfShare'
            break
        }
    }

    PROCESS {

        $Path = Join-Path (Split-Path $Script:MyInvocation.MyCommand.Path) PKWmfInstall
        Write-Verbose $Path

        foreach ($Computer in $ComputerName) {

            if ($Computer -eq 'localhost' -or $Computer -eq '.') {
                Write-Warning "Please use computer name instead of $Computer"
                continue
            }

            if ($PSCmdlet.ShouldProcess($Computer)) {

                $Files = New-PKWmfConfiguration -ComputerName $Computer -Reboot $Reboot -CopyOnly $false
                $Files | ForEach-Object { Write-Verbose "Created $_" }

                #Set-NetFirewallRule -CimSession $Computer -DisplayGroup "File and Printer Sharing" -Profile Domain -Enabled True

                Copy-PKResource -ComputerName $Computer -Module xWindowsUpdate,xPendingReboot

                Set-DscLocalConfigurationManager -Path "$Path" -Verbose

                Start-DscConfiguration -Path "$Path" -ComputerName $Computer -Wait -Verbose -Force
            }
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
                $Removed = $false
            } catch {
                $Removed = $true
            }

            [PSCustomObject]@{
                ComputerName=$Computer
                PowerShell=$Version
                ConfigRemoved=$Removed
            }
        }
    }
}

function Clear-PKWmfConfiguration {
    $Path = Join-Path (Split-Path $Script:MyInvocation.MyCommand.Path) PKWmfInstall

    try {
        Remove-Item "$Path" -Recurse -Force -ea Stop
    } catch {
        Write-Warning "Nothing to clear in $Path"
    }
}

function Remove-PKWmfConfiguration {

[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
param(
    [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [string[]]$ComputerName
)

    PROCESS {

        foreach ($Computer in $ComputerName) {

            if ($PSCmdlet.ShouldProcess($Computer)) {

                Invoke-Command -ComputerName $Computer -ScriptBlock {
                    Remove-Item 'C:\windows\system32\configuration\*.mof'
                    Remove-Item 'C:\Program Files\WindowsPowerShell\Modules\[xc]*' -Recurse -Force
                }
            }
        }

        Get-PKWmfInstall -ComputerName $Computer
    }
}
