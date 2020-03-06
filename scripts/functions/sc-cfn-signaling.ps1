#  Copyright 2016 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
#  This file is licensed to you under the AWS Customer Agreement (the "License").
#  You may not use this file except in compliance with the License.
#  A copy of the License is located at http://aws.amazon.com/agreement/ .
#  This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied.
#  See the License for the specific language governing permissions and limitations under the License.

[CmdletBinding()]
param (
    [string]$StackName,
    [string]$Role,
    [string]$Region
)

# This is used for the final step on the instance userdata to signal back to the CFN stack

$asgMapping = @{
    'IdentityServer'               = "IdentityASG"
    'Collection'                   = "CollectionASG"
    'CollectionSearch'             = "CollectionSearchASG"
    'ReferenceData'                = "ReferenceDataASG"
    'MarketingAutomation'          = "MarketingAutomationASG"
    'MarketingAutomationReporting' = "MarketingAutoRepASG"
    'CortexProcessing'             = "CortexProcessingASG"
    'CortexReporting'              = "CortexReportingASG"
    'CM'                           = "ContentManagementASG"
    'CD'                           = "ContentDeliveryASG"
    'Prc'                          = "ProcessingASG"
    'Rep'                          = "ReportingASG"
}

New-AWSQuickStartResourceSignal -Stack $StackName -Resource $asgMapping.$Role -Region $Region
Write-AWSQuickStartStatus