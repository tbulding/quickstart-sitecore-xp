[CmdletBinding()]
param (
    [string]$filepath,
    [string]$StackName
)

# CloudWatch values
logGroupName  = "$StackName-CD"
LogStreamName = "update-cs-config-" + (Get-Date (Get-Date).ToUniversalTime() -Format "MM-dd-yyyy" )

$connectionString = (Get-SSMParameter -Name "/$StackName/redis/url").Value
#$cwScript = (Get-SSMParameter -Name "/$StackName/user/localqsresourcespath").Value

#$filepath = '/c/dev/resourcefiles/configfiles/ConnectionStrings.config'
$xml = New-Object -TypeName xml
$xml.Load($filepath)
$item = Select-Xml -Xml $xml -XPath '//add[@name="solr.search"]'
$newnode = $item.Node.CloneNode($true)

$newnode.name = 'session'
$newnode.connectionString = $connectionString
$cs = Select-Xml -Xml $xml -XPath '//connectionStrings'
$out = ($cs.Node.AppendChild($newnode)*>&1 | Out-String)

Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString $out

$xml.Save($filepath)