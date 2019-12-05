#  Copyright 2016 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
#  This file is licensed to you under the AWS Customer Agreement (the "License").
#  You may not use this file except in compliance with the License.
#  A copy of the License is located at http://aws.amazon.com/agreement/ .
#  This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied.
#  See the License for the specific language governing permissions and limitations under the License.

[CmdletBinding()]
param (
    [string]$StackName,
    [string]$Role
)

$SCInstallRoot = (Get-SSMParameter -Name "/$StackName/user/localresourcespath").Value
$s3BucketName = (Get-SSMParameter -Name "/$stackName/user/s3bucket/name").Value
$LicencePrefix = (Get-SSMParameter -Name "/$stackName/user/s3bucket/sclicenseprefix").Value
$CertificatePrefix = (Get-SSMParameter -Name "/$StackName/user/s3bucket/certificateprefix").Value
$CertificateName = (Get-SSMParameter -Name "/$StackName/cert/instance/exportname").Value
$RootCertificateName = (Get-SSMParameter -Name "/$StackName/cert/root/exportname").Value
$CertPassword = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-certpass").SecretString).password
$CertSecurePassword = ConvertTo-SecureString $CertPassword -AsPlainText -Force

$logGroupName = $StackName+"-"+$Role
$logStreamLicense = "LicenseFile-" + (Get-Date (Get-Date).ToUniversalTime() -Format "MM-dd-yyyy" )
$logStreamCert = "CertImport-" + (Get-Date (Get-Date).ToUniversalTime() -Format "MM-dd-yyyy" )

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

function cert_import {
    [CmdletBinding()]
    param (
        [string] $CertBucketName,
        [string] $CertPrefix,
        [string] $CertName,
        [string] $RootCertName,
        [securestring] $CertPass
    )
    
    begin {
        $CertBucketLocation = Get-S3BucketLocation -BucketName $CertBucketName
        $CertPath = $CertPrefix + $CertName + '.pfx'
        $RootCertPath = $CertPrefix + $RootCertificateName + '.pfx'
        $CertLocation = 'c:\certificates'
        $LocalCertFile = "$CertLocation\$CertName.pfx"
        $LocalRootCertFile = "$CertLocation\$RootCertName.pfx"
    }
    
    process {
        if (-not (Test-Path -LiteralPath $CertLocation)) {
            -LogGroupName $logGroupName -LogStreamName $logStreamCert -LogString (New-Item -Path $CertLocation -ItemType Directory -Verbose)
        }
        else {
            Write-LogsEntry -LogGroupName $logGroupName -LogStreamName $logStreamCert -LogString "$CertLocation already exists"
        }
        
        Read-S3Object -BucketName $CertBucketName -Region $CertBucketLocation.value -Key $CertPath -File $LocalCertFile
        Read-S3Object -BucketName $CertBucketName -Region $CertBucketLocation.value -Key $RootCertPath -File $LocalRootCertFile
        $RootImport = Import-PfxCertificate -FilePath $LocalRootCertFile -CertStoreLocation Cert:\LocalMachine\Root -Password $CertPass -Exportable
        $InstanceImport = Import-PfxCertificate -FilePath $LocalCertFile -CertStoreLocation Cert:\LocalMachine\My -Password $CertPass -Exportable
        Write-LogsEntry -LogGroupName $logGroupName -LogStreamName $logStreamCert -LogString $RootImport
        Write-LogsEntry -LogGroupName $logGroupName -LogStreamName $logStreamCert -LogString $InstanceImport
    }
    
    end {
        
    }
}

function licence_download {
    [CmdletBinding()]
    param (
        [string] $LicenseBucketName,
        [string] $LicenseObjPrefix,
        [string] $LicenseInstance
    )
    
    begin {
        $bucketlocation = Get-S3BucketLocation -BucketName $LicenseBucketName
    }
    
    process {
        $file = Get-S3Object -BucketName $LicenseBucketName -Region $bucketlocation.value | Where-Object { ($_.Key -like "$LicenseObjPrefix*license.zip") -or ($_.Key -like "$LicencePrefix*license.xml") }

        if (($file.key -like '*license.zip')) {
            Write-LogsEntry -LogGroupName $logGroupName -LogStreamName $logStreamLicense -LogString (Read-S3Object -BucketName $LicenseBucketName -Region $bucketlocation.value -Key $file.key -File "$LicenseInstance\license.zip" | Out-String)
            Write-LogsEntry -LogGroupName $logGroupName -LogStreamName $logStreamLicense -LogString (Expand-Archive -LiteralPath "$LicenseInstance\license.zip" -DestinationPath $LicenseInstance -Force -Verbose *>&1 | Out-String)
        }
        
        elseif (($file.key -like '*license.xml')) {
            Write-LogsEntry -LogGroupName $logGroupName -LogStreamName $logStreamLicense -LogString (Read-S3Object -BucketName $LicenseBucketName -Region $bucketlocation.value -Key $file.key -File "$LicenseInstance\license.xml")
        }
        
    }
    
    end {
        
    }
}

cert_import -CertBucketName $s3BucketName -CertPrefix $CertificatePrefix -CertName $CertificateName -RootCertName $RootCertificateName -CertPass $CertSecurePassword
licence_download -LicenseBucketName $s3BucketName -LicenseObjPrefix $LicencePrefix -LicenseInstance $SCInstallRoot