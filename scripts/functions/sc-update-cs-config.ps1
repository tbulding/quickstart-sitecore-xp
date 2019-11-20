[CmdletBinding()]
param (
    [string]$filepath,
    [string]$connectionString
)
#$filepath = '/c/dev/resourcefiles/configfiles/ConnectionStrings.config'
$xml = New-Object -TypeName xml
$xml.Load($filepath)
$item = Select-Xml -Xml $xml -XPath '//add[@name="security"]'
$newnode = $item.Node.CloneNode($true)

$newnode.name = 'session'
$newnode.connectionString = $connectionString
$cs = Select-Xml -Xml $xml -XPath '//connectionStrings'
$cs.Node.AppendChild($newnode)

$xml.Save($filepath)