[CmdletBinding()]
param (
    [string]$stackName,
    [string]$QSS3BucketName,
    [string]$QSS3KeyPrefix
)
$logGroupName = "$stackName-ssm-bootstrap"
$S3BucketName = (Get-SSMParameter -Name "/$stackName/user/s3bucket/name").Value # The bucket containing the Sitecore 9.2 install files and sitecore license.zip file
$S3ScResourcesPrefix = (Get-SSMParameter -Name "/$stackName/user/s3bucket/scresourcesprefix").Value # The prefix where the install files are located
$localPath = (Get-SSMParameter -Name "/$stackName/user/localresourcespath").Value # Path on the instance where the files will be located
$qslocalPath = (Get-SSMParameter -Name "/$stackName/user/localqsresourcespath").Value # Path on the instance where the Quick Start files will be located

function Write-LogsEntry {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string] $logGroupName,
        [Parameter(Mandatory = $true)]
        [string] $LogStreamName,
        [Parameter(Mandatory = $true)]
        [string] $LogString
    )
    Process {
        #Determine if the LogGroup Exists
        If (-Not (Get-CWLLogGroup -LogGroupNamePrefix $logGroupName)) {
            New-CWLLogGroup -LogGroupName $logGroupName
        }
        #Determine if the LogStream Exists
        If (-Not (Get-CWLLogStream -LogGroupName $logGroupName -LogStreamName $LogStreamName)) {
            $splat = @{
                LogGroupName  = $logGroupName
                LogStreamName = $logStreamName
            }
            New-CWLLogStream @splat
        }
        $logEntry = New-Object -TypeName 'Amazon.CloudWatchLogs.Model.InputLogEvent'
        $logEntry.Message = $LogString
        $logEntry.Timestamp = (Get-Date).ToUniversalTime()
        #Get the next sequence token
        $SequenceToken = (Get-CWLLogStream -LogGroupName $logGroupName -LogStreamNamePrefix $logStreamName).UploadSequenceToken
        if ($SequenceToken) {
            $splat = @{
                LogEvent      = $logEntry
                LogGroupName  = $logGroupName
                LogStreamName = $logStreamName
                SequenceToken = $SequenceToken
            }
            Write-CWLLogEvent @splat
        }
        else {
            $splat = @{
                LogEvent      = $logEntry
                LogGroupName  = $logGroupName
                LogStreamName = $logStreamName
            }
            Write-CWLLogEvent @splat
        }
    }
}
$logStreamName = "BaseImage-" + (Get-Date (Get-Date).ToUniversalTime() -Format "MM-dd-yyyy" )
#Modify Registry disable IE enhanced security
$path = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\"
New-ItemProperty -Name 'IsInstalled' -path $path -Value '0' -PropertyType DWORD -Force
New-ItemProperty -Name "IsInstalled" -path "$path{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Value "00000000" -PropertyType DWORD -Force
New-ItemProperty -Name "IsInstalled" -path "$path{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Value "00000000" -PropertyType DWORD -Force
Write-LogsEntry -LogGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'Disabled IE Enhanced Security'
# Get Sitecore install files from S3
Write-LogsEntry -LogGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'Initiating Sitecore resource files download'
$files = Get-S3Object -BucketName $s3BucketName | Where-Object { ($_.Key -like "$S3ScResourcesPrefix*.zip") }
foreach ($file in $files) {
    $filename = Split-path -Path $file.key -leaf
    Read-S3Object -BucketName $s3BucketName -Key $file.key -File "$localpath\$filename"
    if ($? -eq 'true') { Write-LogsEntry -LogGroupName $logGroupName -LogStreamName $LogStreamName -LogString "Downloaded $filename" }
    if (($file.key -like '*configuration*')) {
        Write-LogsEntry -LogGroupName $logGroupName -LogStreamName $LogStreamName -LogString (Expand-Archive -LiteralPath "$localpath\$filename" -DestinationPath $localpath -Force -Verbose *>&1 | Out-String)
    }
}
#Get AWS Custom install JSON Role files
$customjson = $QSS3KeyPrefix + "scripts/custom/"
Write-LogsEntry -LogGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'Initiating AWS Custom install JSON Role files download'
Write-LogsEntry -LogGroupName $logGroupName -LogStreamName $LogStreamName -LogString (Read-S3Object -BucketName $QSS3BucketName -KeyPrefix $customjson -Folder "$localpath\aws-custom")

#Extract QuickStart MS Utilities
Expand-Archive -LiteralPath "$qslocalPath\utilities\AWSQuickStart.zip" -DestinationPath "C:\Windows\system32\WindowsPowerShell\v1.0\Modules\" -Force -Verbose *>&1
if ($? -eq 'true') {
    Write-LogsEntry -LogGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'Successfully extracted Quick Start Microsoft Utilities'
    }
else {
    Write-LogsEntry -LogGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'Failed to extracted Quick Start Microsoft Utilities'
    }

# Install NuGet provider
Install-PackageProvider -Name NuGet -Force
if ($? -eq 'true') {
    Write-LogsEntry -LogGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'Successfully installed NuGet Package Privider'
    }
else {
    Write-LogsEntry -LogGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'Failed to install NuGet Package Privider'
    }

# Register Sitecore repository
Register-PSRepository -Name SitecoreGallery -SourceLocation https://sitecore.myget.org/F/sc-powershell/api/v2 -InstallationPolicy Trusted  | Out-Null
Write-LogsEntry -LogGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'Registered Repository SiteCoreGallery'
# Install IIS Management Scripting Tools
Get-WindowsOptionalFeature -Online -FeatureName IIS-ManagementScriptingTools
Write-LogsEntry -LogGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'Installed IIS Management Scripting Tools'
# Install SQL Server Module
Install-Module SQLServer -Force
Write-LogsEntry -LogGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'Installed SQL Server Module'
# Modified registry key that will assist with the error about trying to edit a deleted registry entry
New-ItemProperty -Name DisableForceUnload -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Value "1" -PropertyType DWORD -Force
#Install SiteCore Install Framework
Write-LogsEntry -LogGroupName $logGroupName -LogStreamName $LogStreamName -LogString (Install-Module SitecoreInstallFramework -Force -Verbose *>&1 | Out-String)
#Install-Module SitecoreInstallFramework -Force
Write-LogsEntry -LogGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'Installed Module SitecoreInstallFramework'
# Install Sitecore configuration
Write-LogsEntry -LogGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'Initiating installation of Sitecore Prerequisites'
Install-SitecoreConfiguration -Path "$localPath\Prerequisites.json" -Verbose *>&1 | Tee-Object -FilePath "$localPath\Prerequisites.log"
Write-LogsEntry -LogGroupName $logGroupName -LogStreamName $LogStreamName -LogString $(Get-Content -Path "$localPath\Prerequisites.log" -raw)
Write-LogsEntry -LogGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'Installed Sitecore Configuration'
Write-SSMParameter -Name "/$stackName/instance/image/custom" -Type "String" -Value (Invoke-RestMethod -uri http://169.254.169.254/latest/meta-data/instance-id) -Overwrite:$true
Write-LogsEntry -LogGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'Added instance ID to parameter store'