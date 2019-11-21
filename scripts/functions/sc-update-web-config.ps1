[CmdletBinding()]
param (
    [string]$filepath
)
#$filepath = '/c/dev/resourcefiles/configfiles/Web.config'
$xml = New-Object -TypeName xml
$xml.Load($filepath)
$item = Select-Xml -Xml $xml -XPath '//sessionState'

#Remove the node
$null = $item.Node.ParentNode.RemoveChild($item.Node)

#Create the replacement node
$sessionState = $xml.CreateElement("sessionState")
$sessionState.SetAttribute("mode", "Custom")
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
