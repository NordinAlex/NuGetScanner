# NuGet-packages Vulnerability Scanner

This repository contains scripts designed for Azure DevOps Build Pipeline to detect vulnerabilities in NuGet packages used in both .NET Core and .NET Framework projects.

## Scripts

### .NET Core Script

This script detects vulnerabilities in NuGet packages used in a .NET Core project.

#### Usage

To use this script, follow these steps:

1. Go to Azure DevOps Build Pipeline.
2. Add a PowerShell Task to the Pipeline.
3. In the PowerShell Task, choose the type "Inline" and paste this script:

    ```powershell
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
        } elseif ($low) {
            Write-Host "##[warning] Low vulnerability found."
        } else {
            Write-Host "##[section] No vulnerabilities found."
            Write-Host "##vso[task.complete result=Succeeded;]DONE"
        }   
    }
    catch {
        # Handle any errors that occur during the execution
        Write-Host "##vso[task.logissue type=error;] An error occurred: " + $_.Exception.Message
        Write-Host "##vso[task.complete result=Failed;]"   
    }
    ```

4. Save and run the Pipeline.

### .NET Framework Script

This script detects vulnerabilities in NuGet packages used in a .NET Framework project.

#### Usage

To use this script, follow these steps:

1. Go to Azure DevOps Build Pipeline.
2. Add a PowerShell Task to the Pipeline.
3. In the PowerShell Task, choose the type "Inline" and paste this script:

    ```powershell
      #==============================================================================
      # Name         : NuGet-packages Vulnerability Scanner
      # Description  : This is for Azure DevOps Build Pipeline to detect vulnerabilities in NuGet packages used in a .NET Framework project
      # Version      : 0.0.1
      # Author       : Alex Nordin
      # License      : MIT License 2024
      # Help         : https://github.com/AlexNordin-dev/NuGetPackagesVulnerabilityScanner
      #==============================================================================
      
      # The path where the PowerShell script is temporarily located
      $ScriptPath = $env:AGENT_TEMPDIRECTORY
      # Path to the project's root folder
      $projectRoot = $env:BUILD_REPOSITORY_LOCALPATH
      
      
      # Download all csproj files under the project root folder and its subfolders without everything in "obj and bin"
      $csprojFiles = Get-ChildItem -Path $projectRoot -Filter *.csproj -Recurse | Where-Object { $_.PSIsContainer -eq $false -and $_.FullName -notlike "*\obj\*" -and $_.FullName -notlike "*\bin\*" -and $_.FullName -notlike "*\TemporaryMapp\*" -and $_.Name }
      
      if ($csprojFiles.Count -gt 0) {
          foreach ($csprojFile in $csprojFiles) {
              $projectName = [System.IO.Path]::GetFileNameWithoutExtension($csprojFile.Name)
      
              try {
                  # Update $projectlocation based on the script's location in a new folder
                  $Tprojectlocation = Join-Path $ScriptPath "TemporaryMapp\$projectName\$projectName.csproj"
      
                  # Create the folder if it doesn't already exist
                  $folderPath = Split-Path $Tprojectlocation
                  if (-not (Test-Path $folderPath)) {
                      New-Item -Path $folderPath -ItemType Directory -Force
                  }
      
                  [System.Collections.ArrayList]$packageslist = @();
      
                  Function ListAllPackages ($BaseDirectory) {
                      ## Write-Host "Listar ut alla Packages - Detta kan ta en stund ..."
                      $PACKAGECONFIGS = Get-ChildItem -Recurse -Force $BaseDirectory -ErrorAction SilentlyContinue | 
                      Where-Object { $_.PSIsContainer -eq $false -and $_.FullName -notlike "*\obj\*" -and $_.FullName -notlike "*\bin\*" -and $_.FullName -notlike "*\TemporaryMapp\*" -and $_.Name -eq "packages.config" }
      
                      ForEach ($PACKAGECONFIG in $PACKAGECONFIGS) {
                         
                          $path = $PACKAGECONFIG.FullName
      
                          [xml]$packages = Get-Content $path                        
      
                          foreach ($package in $packages.packages.package) {                               
                              if ($package.developmentDependency -ne "true") {
                                  $entry = "<PackageReference Include=`"$($package.id)`" Version=`"$($package.version)`" Framework=`"$($package.targetFramework)`" />"
                                  $packageslist.Add($entry)
                                  
                              }
                          }
                      }
                      Write-Host "##[command] Processing $($PACKAGECONFIG.FullName)"
                  }
      
                  # Function to create a .csproj file for a project  
                  $Tprojectloca = Join-Path $ScriptPath "TemporaryMapp\$projectName"
                  Function CreateProjectFile ($Tprojectloca) {                   
                      $uniqueList = $packageslist | Sort-Object  | Get-Unique
      
                      $start = "<Project Sdk=`"Microsoft.NET.Sdk.Web`">
      
                      <PropertyGroup>
                          <TargetFramework>net48</TargetFramework>
                      </PropertyGroup>
                  
                      <ItemGroup>"
      
                      $end = "</ItemGroup>
      
                              </Project>"
      
                      $total = $start + $uniqueList + $end
                      $total | Out-File $Tprojectlocation
                  }         
      
                  try {                
                      ListAllPackages $csprojFile.DirectoryName > $null          
      
                      CreateProjectFile $Tprojectlocation 
                      # dotnet restore $projectName.csproj
                      $packageslist.Clear()
                  }
                  catch {
                      Write-Host $_.Exception.Message
                  }
      
              }
              catch {
                  Write-Host "Ett fel uppstod vid hantering av $($csprojFile.FullName): $_"
              }
          }
      
          # Create the solution in the TemporaryMapp folder
          $solutionPath = Join-Path $ScriptPath "TemporaryMapp\TemporaryMapp.sln"
          dotnet new sln -n TemporaryMapp -o $ScriptPath\TemporaryMapp > $null
      
          # Add project files to the solution
          foreach ($csprojFile in $csprojFiles) {
              $projectName = [System.IO.Path]::GetFileNameWithoutExtension($csprojFile.Name)
              $projectlocation = Join-Path $ScriptPath "TemporaryMapp\$projectName\$projectName.csproj"
              dotnet sln $solutionPath add $projectlocation > $null
          }
      
          # Change to the project folder
          Set-Location $ScriptPath\TemporaryMapp
          dotnet restore > $null
           
         
          Write-Host "  ---------------- Security analysis of NuGet packages ---------------------"
       
      
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
                  Write-Host "##vso[task.logissue type=error;] Task stopped due to high, moderate or critical vulnerabilities found"
                  Write-Host "##vso[task.complete result=Failed;]"
              }
              elseif ($low) {
                  Write-Host "##[warning] Low vulnerability found."
              }
              else {
                  Write-Host "##[section]  No vulnerabilities found. "     
                  Write-Host "##vso[task.complete result=Succeeded;]DONE"
              }   
          }
          catch {
              # Handle any errors that occur during the execution
              Write-Host "##vso[task.logissue type=error;] An error occurred: " + $_.Exception.Message
              Write-Host "##vso[task.complete result=Failed;]"   
          }
      }
      else {
          # If no csproj files are found in the path
          Write-Host "No csproj files found in path."
      }
    ```

4. Save and run the Pipeline.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.


