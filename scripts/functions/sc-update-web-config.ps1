[CmdletBinding()]
param (
    [string]$SCQSPrefix
)


$SCPrefix = (Get-SSMParameter -Name "/$SCQSPrefix/user/sitecoreprefix").Value
$LocalQSResources = (Get-SSMParameter -Name "/$SCQSPrefix/user/localqsresourcespath").Value # c:\quickstart\scripts
$filepath = "C:\inetpub\wwwroot\$SCPrefix.CD\Web.config"


# CloudWatch values
$logGroupName  = "$SCQSPrefix-CD"
$LogStreamName = "update-web-config-" + (Get-Date (Get-Date).ToUniversalTime() -Format "MM-dd-yyyy" )

Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString "Updating web-config file for Redis session state"

#$filepath = '/c/dev/resourcefiles/configfiles/Web.config'
$xml = New-Object -TypeName xml
$xml.Load($filepath)
$item = Select-Xml -Xml $xml -XPath '//sessionState'

#Remove the node
$null = $item.Node.ParentNode.RemoveChild($item.Node)

#Create the replacement node
$sessionState = $xml.CreateElement("sessionState")
$sessionState.SetAttribute("mode", "custom")
$sessionState.SetAttribute("customProvider", "redis")
$sessionState.SetAttribute("timeout", "20")

$providers = $xml.CreateElement("providers")

$add = $xml.CreateElement("add")
$add.SetAttribute("name", "redis")
$add.SetAttribute("type", "Sitecore.SessionProvider.Redis.RedisSessionStateProvider, Sitecore.SessionProvider.Redis")
$add.SetAttribute("connectionString", "session")
$add.SetAttribute("pollingInterval", "2")
$add.SetAttribute("applicationName", "private")

$providers.AppendChild($add)
$sessionState.AppendChild($providers)
$xml.configuration.'system.web'.AppendChild($sessionState)
$xml.Save($filepath)
$sessionState.AppendChild($providers)
$out = ($xml.configuration.'system.web'.AppendChild($sessionState)*>&1 | Out-String) 

Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString $out


$xml.Save($filepath)
