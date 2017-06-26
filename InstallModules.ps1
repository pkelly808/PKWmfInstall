if (!(Get-Module xWindowsUpdate -ListAvailable | Where-Object Version -eq '1.0')) {
    Install-Module xWindowsUpdate -RequiredVersion 1.0
}

if (!(Get-Module xPendingReboot -ListAvailable | Where-Object Version -eq '0.1.0.2')) {
    Install-Module xPendingReboot -RequiredVersion 0.1.0.2
}
