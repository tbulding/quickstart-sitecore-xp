[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$hostedZoneID,
    [string]$SCQSPrefix
)

$urlsuffix = (Get-SSMParameter -Name "/$SCQSPrefix/service/internaldns").Value 
$SolrDNS = 'solrdev.' + $urlsuffix
$SolrURL = (Get-SSMParameter -Name "/${SCQSPrefix}/user/solruri").Value
$SolrVersion = "8.1.1"
$SolrPort = 8983
$SolrCorePrefix = (Get-SSMParameter -Name "/$SCQSPrefix/user/solrcoreprefix").Value # Path on the instance where the files will be located
$localPath = (Get-SSMParameter -Name "/$SCQSPrefix/user/localresourcespath").Value # Path on the instance where the files will be located
$localLogPath = "$localPath\logs" # Path on the instance where the log files will be located
$qslocalPath = (Get-SSMParameter -Name "/$SCQSPrefix/user/localqsresourcespath").Value # Path on the instance where the Quick Start files will be located
# Route53 variables
$recordType = 'CNAME'
$recordTTL = '300'
$hostname = Invoke-RestMethod -uri http://169.254.169.254/latest/meta-data/hostname
# Certificate Export Parameters
$localCertpath = "$localPath\certificates" # Path on the instance where the log files will be located
$RawPassword = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-certpass").SecretString).password
$ExportPassword = ConvertTo-SecureString $RawPassword -AsPlainText -Force
$S3BucketName = (Get-SSMParameter -Name "/$SCQSPrefix/user/s3bucket/name").Value
$S3BucketCertificatePrefix = (Get-SSMParameter -Name "/$SCQSPrefix/user/s3bucket/certificateprefix").Value

# Check and create logs path
If(!(test-path $localLogPath))
{
      New-Item -ItemType Directory -Force -Path $localLogPath
}
If(!(test-path $localCertpath))
{
      New-Item -ItemType Directory -Force -Path $localCertpath
}

# CloudWatch values
$logGroupName = "$SCQSPrefix-solr-dev-install"
$logStreamName = "Solr-Install-" + (Get-Date (Get-Date).ToUniversalTime() -Format "MM-dd-yyyy" )

Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'Starting deployment of Solr Dev server'

# Adding / Updating R53 entry for Solr instance
$RecordSetsResponse = (Get-R53ResourceRecordSet -HostedZoneId $hostedZoneID -StartRecordName $SolrDNS -StartRecordType $recordType).ResourceRecordSets
if (-not $RecordSetsResponse) {
    Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'R53 Record for ' + $SolrDNS + 'does not exist. Creating.'
    $R53Comment = "Creating new R53 CNAME record for Solr Developer instance"
}
else {
    Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'R53 Record for ' + $SolrDNS + 'exists. Updating.' 
    $R53Comment = "Updating existing R53 CNAME record for Solr Developer instance"
}

$Change = New-Object Amazon.Route53.Model.Change
$Change.Action = "UPSERT"
$Change.ResourceRecordSet = New-Object Amazon.Route53.Model.ResourceRecordSet
$Change.ResourceRecordSet.Name = "$SolrDNS"
$Change.ResourceRecordSet.TTL = "$recordTTL"
$Change.ResourceRecordSet.Type = "$recordType"
$Change.ResourceRecordSet.ResourceRecords.Add(@{Value="$hostname"})

$R53Params = @{
    HostedZoneId = $hostedZoneID
    ChangeBatch_Comment = $R53Comment
    ChangeBatch_Change = $Change
    Force = $Force
}
$R53Response = Edit-R53ResourceRecordSet @R53Params
Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString $R53Response
# Write new Solr URL to Parameter Store
# $SolrURL = "https://" + $SolrDNS + ":" + $SolrPort + "/solr"
# Write-SSMParameter -Name "/$SCQSPrefix/user/solruri" -Type "String" -Value $SolrURL -Overwrite:$true
# Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString "Added Solr URL ($SolrURL) to Parameter Store"

# Installing Solr
$SolrParameters = @{
    SolrVersion               = $SolrVersion
    SolrDomain                = $SolrDNS
    SolrPort                  = $SolrPort
    # SolrServicePrefix         = ""
    # SolrInstallRoot           = "C:\\"
    # SolrSourceURL             = "http://archive.apache.org/dist/lucene/solr"
    # JavaDownloadURL           = "https://github.com/AdoptOpenJDK/openjdk8-binaries/releases/download/jdk8u222-b10/OpenJDK8U-jre_x64_windows_hotspot_8u222b10.zip"
    # ApacheCommonsDaemonURL    = "http://archive.apache.org/dist/commons/daemon/binaries/windows/commons-daemon-1.1.0-bin-windows.zip"
    # TempLocation              = "SIF-Default"
    # ServiceLocation           = "HKLM:SYSTEM\\CurrentControlSet\\Services"
}

Install-SitecoreConfiguration @SolrParameters -Path "$localPath\Solr-SingleDeveloper.json" -Verbose *>&1 | Tee-Object "$localLogPath\solr-install.log"
Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString $(Get-Content -Path "$localLogPath\solr-install.log" -raw)

# Configuring Solr Cores
$sitecoreSolrCores = @{
    SolrUrl = "$SolrURL"
    SolrRoot = "c:\\solr-$SolrVersion"
    SolrService = "Solr-$SolrVersion"
    # BaseConfig = ""
    CorePrefix = "$SolrCorePrefix"
}

Install-SitecoreConfiguration @sitecoreSolrCores -Path "$localPath\sitecore-solr.json" -Verbose *>&1 | Tee-Object "$localLogPath\solr-cores-install.log"
Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString $(Get-Content -Path "$localLogPath\solr-cores-install.log" -raw)

Install-SitecoreConfiguration @sitecoreSolrCores -Path "$localPath\xconnect-solr.json" -Verbose *>&1 | Tee-Object "$localLogPath\xconnect-cores-install.log"
Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString $(Get-Content -Path "$localLogPath\xconnect-cores-install.log" -raw)

# Export the Solr certificate in the personal store for installation on the Sitecore Roles
$solrcert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.FriendlyName -like "*solr*" }
$certThumbprint = $solrcert.Thumbprint
$certExportName = "$localCertpath\solrdev.pfx"

Export-PfxCertificate -Cert "Cert:\LocalMachine\My\$certThumbprint" -Password $ExportPassword -FilePath $certExportName -Verbose *>&1 | Tee-Object "$localLogPath\solr-cert.log"
Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString $(Get-Content -Path "$localLogPath\solr-cert.log" -raw)

# Copy up to S3
$key = $S3BucketCertificatePrefix + "solrdev.pfx"
Write-S3Object -BucketName $S3BucketName -File $certExportName -Key $key -Verbose *>&1 | Tee-Object "$localLogPath\solr-cert-upload.log"
Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString $(Get-Content -Path "$localLogPath\solr-cert-upload.log" -raw)