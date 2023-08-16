$modulePath = "$PSScriptRoot\PoshSophos"

$moduleManifest = Import-PowerShellDataFile -Path ('{0}\*.psd1' -f $modulePath)

$requiredModules = $moduleManifest.RequiredModules.ModuleName

if ($requiredModules) {

    foreach ($module in $requiredModules) {

        $modules = Get-Module -Name $module -ListAvailable

        if ($null -eq $modules) {

            Install-Module -Name $module -Force -Scope CurrentUser
        }
    }
}

Publish-Module -Path $modulePath -NuGetApiKey $Env:APIKEY