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