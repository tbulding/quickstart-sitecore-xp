[CmdletBinding()]
param (
    [string]$filepath,
    [string] $StackName
)

$connectionString = (Get-SSMParameter -Name "/$StackName/redis/url").Value

#$filepath = '/c/dev/resourcefiles/configfiles/ConnectionStrings.config'
$xml = New-Object -TypeName xml
$xml.Load($filepath)
$item = Select-Xml -Xml $xml -XPath '//add[@name="solr.search"]'
$newnode = $item.Node.CloneNode($true)

$newnode.name = 'session'
$newnode.connectionString = $connectionString
$cs = Select-Xml -Xml $xml -XPath '//connectionStrings'
$out = ($cs.Node.AppendChild($newnode)*>&1 | Out-String)
#region  logging
$parms = @{
    logGroupName  = "$StackName-update-config-files"
    LogStreamName = "cs-config-" + (Get-Date (Get-Date).ToUniversalTime() -Format "MM-dd-yyyy" )
    LogString     = $out
}
./sc-write-logsentry.ps1 @parms
#endregion

$xml.Save($filepath)