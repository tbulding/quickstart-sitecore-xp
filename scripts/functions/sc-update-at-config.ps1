#  Copyright 2016 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
#  This file is licensed to you under the AWS Customer Agreement (the "License").
#  You may not use this file except in compliance with the License.
#  A copy of the License is located at http://aws.amazon.com/agreement/ .
#  This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied.
#  See the License for the specific language governing permissions and limitations under the License.

[CmdletBinding()]

$searchString = '<add name="InProc" type="System.Web.SessionState.InProcSessionStateStore" />'
$replaceString = '<add name="redis" type="Sitecore.SessionProvider.Redis.RedisSessionStateProvider,  
                            Sitecore.SessionProvider.Redis"
                            connectionString="sharedSession"
                            pollingInterval="2"
                            applicationName="shared"/>'
#$filePath = 'C:\inetpub\wwwroot\sc.CD\App_Config\Sitecore\Marketing.Tracking\Sitecore.Analytics.Tracking.config'
$filePath = '~/Downloads/Sitecore.Analytics.Tracking.config'

$contents = Get-Content -Path $filePath -Raw
$newContent = $contents -replace $searchString, $replaceString

$newContent | Set-Content -Path $filePath
