#==============================================================================
# Name         : NuGet-packages Vulnerability Scanner
# Description  : This is for Azure DevOps Build Pipeline to detect vulnerabilities in NuGet packages used in a .NET Core project
# Version      : 0.0.1
# Author       : Alex Nordin
# License      : MIT License 2024
# Help         : https://github.com/AlexNordin-dev/NuGetPackagesVulnerabilityScanner
#==============================================================================

# Path to the project's root folder
$projectRoot = $env:BUILD_REPOSITORY_LOCALPATH
Set-Location $projectRoot


Write-Host "------------------- Security analysis of NuGet packages -------------------"

try {
    # Run the command to list vulnerable packages
    $result = dotnet list package --vulnerable --include-transitive
    Write-Output $result

    # Search for different levels of vulnerabilities
    $high = $result | Select-String -Pattern 'High' -CaseSensitive
    $low = $result | Select-String -Pattern 'Low' -CaseSensitive
    $moderate = $result | Select-String -Pattern 'Moderate' -CaseSensitive
    $critical = $result | Select-String -Pattern 'Critical' -CaseSensitive
    
    # Determine the result based on the vulnerabilities found
    if ($high -or $moderate -or $critical) {
        Write-Host "##vso[task.logissue type=error;] Task stopped due to high, moderate, or critical vulnerabilities found."
        Write-Host "##vso[task.complete result=Failed;]"
    }
    elseif ($low) {
        Write-Host "##[warning] Low vulnerability found."
    }
    else {
        Write-Host "##[section] No vulnerabilities found."
        Write-Host "##vso[task.complete result=Succeeded;]DONE"
    }   
}
catch {
    # Handle any errors that occur during the execution
    Write-Host "##vso[task.logissue type=error;] An error occurred: " + $_.Exception.Message
    Write-Host "##vso[task.complete result=Failed;]"   
}
