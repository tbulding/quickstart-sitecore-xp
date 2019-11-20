[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [ValidateSet(
        'DbResources',
        'IdentityServer',
        'Collection',
        'CollectionSearch',
        'ReferenceData',
        'MarketingAutomation',
        'MarketingAutomationReporting',
        'CortexProcessing',
        'CortexReporting',
        'CM',
        'CD',
        'Prc',
        'Rep'
    )]
    [string]
    $Role,
    [Parameter(Mandatory)]
    $StackName,
    [Parameter(Mandatory)]
    $Region
)
If (![Environment]::Is64BitProcess) {
    Write-Host "Please run 64-bit PowerShell" -foregroundcolor "yellow"
    return
}
Import-Module SitecoreInstallFramework

$urlsuffix = (Get-SSMParameter -Name "/$StackName/service/internaldns").Value
#region Role Mapping
$roleMapping = @{
    'IdentityServer'               = "identity"
    'Collection'                   = "coll"
    'CollectionSearch'             = "collsearch"
    'ReferenceData'                = "refdata"
    'MarketingAutomation'          = "mktauto"
    'MarketingAutomationReporting' = "mktautorep"
    'CortexProcessing'             = "cortexproc"
    'CortexReporting'              = "cortexrep"
    'CM'                           = "contentmgmt"
    'CD'                           = "contentdel"
    'Prc'                          = "proc"
    'Rep'                          = "rep"
}
#endregion

#region Parameter Values
$parameters = @{
    Prefix                               = (Get-SSMParameter -Name "/$StackName/user/sitecoreprefix").Value
    SCInstallRoot                        = (Get-SSMParameter -Name "/$StackName/user/localresourcespath").Value
    PasswordRecoveryUrl                  = (Get-SSMParameter -Name "/$StackName/service/passwordrecoveryurl").Value
    allowedCorsOrigins                   = (Get-SSMParameter -Name "/$StackName/service/allowedCorsOrigins").Value
    Environment                          = (Get-SSMParameter -Name "/$StackName/user/environment").Value
    LogLevel                             = (Get-SSMParameter -Name "/$StackName/user/logLevel").Value
    SolrCorePrefix                       = (Get-SSMParameter -Name "/$StackName/user/solrcoreprefix").Value
    SolrUrl                              = (Get-SSMParameter -Name "/$StackName/user/solruri").Value
    InstanceCertificateThumbPrint        = (Get-SSMParameter -Name "/$stackName/cert/instance/thumbprint").Value
    SQLServer                            = (Get-SSMParameter -Name "/$StackName/sql/server").Value
    # IdentityServerDNS                    = $roleMapping.IdentityServer + '.' + $urlsuffix
    IdentityServerDNS                    = (Get-SSMParameter -Name "/$StackName/service/isdns").Value
    CollectionDNS                        = $roleMapping.Collection + '.' + $urlsuffix
    CollectionSearchDNS                  = $roleMapping.CollectionSearch + '.' + $urlsuffix
    ReferenceDataDNS                     = $roleMapping.ReferenceData + '.' + $urlsuffix
    MarketingAutomationDNS               = $roleMapping.MarketingAutomation + '.' + $urlsuffix
    MarketingAutomationReportingDNS      = $roleMapping.MarketingAutomationReporting + '.' + $urlsuffix
    CortexProcessingDNS                  = $roleMapping.CortexProcessing + '.' + $urlsuffix
    CortexReportingDNS                   = $roleMapping.CortexReporting + '.' + $urlsuffix
    # CMDNS                                = $roleMapping.CM + '.' + $urlsuffix
    CMDNS                                = (Get-SSMParameter -Name "/$StackName/service/cmdns").Value
    # CDDNS                                = $roleMapping.CD + '.' + $urlsuffix
    CDDNS                                = (Get-SSMParameter -Name "/$StackName/service/cddns").Value
    PrcDNS                               = $roleMapping.Prc + '.' + $urlsuffix
    RepDNS                               = $roleMapping.Rep + '.' + $urlsuffix
    XConnectCollectionService            = "https://" + $roleMapping.Collection + '.' + $urlsuffix
    XConnectSearchService                = "https://" + $roleMapping.Collection + '.' + $urlsuffix
    XConnectCollectionSearchService      = "https://" + $roleMapping.CollectionSearch + '.' + $urlsuffix
    XConnectReferenceDataService         = "https://" + $roleMapping.ReferenceData + '.' + $urlsuffix
    SitecoreIdentityAuthority            = "https://" + $roleMapping.IdentityServer + '.' + $urlsuffix
    MarketingAutomationOperationsService = "https://" + $roleMapping.MarketingAutomation + '.' + $urlsuffix
    MarketingAutomationReportingService  = "https://" + $roleMapping.MarketingAutomationReporting + '.' + $urlsuffix
    CortexReportingService               = "https://" + $roleMapping.CortexReporting + '.' + $urlsuffix
    ProcessingService                    = "https://" + $roleMapping.Prc + '.' + $urlsuffix
    ReportingService                     = "https://" + $roleMapping.Rep + '.' + $urlsuffix
}
#endregion

#region Secrets Manager Values
$secrets = @{
    #InstanceCertificateThumbPrint  = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-certificate-export").SecretString).thumbprint
    SitecoreIdentitySecret         = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sitecoreidentitysecret").SecretString).secret
    SitecoreAdminPassword          = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sitecoreadmin").SecretString).password
    ReportingServiceApiKey         = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-reportingserviceapikey").SecretString).apikey
    ClientSecret                   = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-clientsecret").SecretString).secret
    SqlAdminUser                   = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqladmin").SecretString).username
    SqlAdminPassword               = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqladmin").SecretString).password
    SqlSecurityUser                = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlsecurity").SecretString).username
    SqlSecurityPassword            = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlsecurity").SecretString).password
    SqlCollectionUser              = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlcollection").SecretString).username
    SqlCollectionPassword          = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlcollection").SecretString).password
    SqlMessagingUser               = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlmessaging").SecretString).username
    SqlMessagingPassword           = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlmessaging").SecretString).password
    SqlProcessingEngineUser        = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlprocessingengine").SecretString).username
    SqlProcessingEnginePassword    = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlprocessingengine").SecretString).password
    SqlReportingUser               = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlreporting").SecretString).username
    SqlReportingPassword           = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlreporting").SecretString).password
    SqlCoreUser                    = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlcore").SecretString).username
    SqlCorePassword                = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlcore").SecretString).password
    SqlMasterUser                  = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlmaster").SecretString).username
    SqlMasterPassword              = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlmaster").SecretString).password
    SqlWebUser                     = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlweb").SecretString).username
    SqlWebPassword                 = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlweb").SecretString).password
    SqlReferenceDataUser           = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlreferencedata").SecretString).username
    SqlReferenceDataPassword       = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlreferencedata").SecretString).password
    SqlFormsUser                   = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlforms").SecretString).username
    SqlFormsPassword               = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlforms").SecretString).password
    SqlExmMasterUser               = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlexmmaster").SecretString).username
    SqlExmMasterPassword           = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlexmmaster").SecretString).password
    SqlProcessingPoolsUser         = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlprocessingpools").SecretString).username
    SqlProcessingPoolsPassword     = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlprocessingpools").SecretString).password
    SqlMarketingAutomationUser     = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlmarketingautomation").SecretString).username
    SqlMarketingAutomationPassword = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlmarketingautomation").SecretString).password
    SqlProcessingTasksUser         = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlprocessingtasks").SecretString).username
    SqlProcessingTasksPassword     = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$StackName-sqlprocessingtasks").SecretString).password
}

#endregion

#region local values
$local = @{
    ComputerName            = $(Invoke-RestMethod -uri http://169.254.169.254/latest/meta-data/hostname)
    SiteName                = "$($parameters.prefix).$Role"
    Package                 = (Get-ChildItem -LiteralPath "$($parameters.SCInstallRoot)" -Filter "*$Role.scwdp.zip").FullName
    jsonPath                = (Get-ChildItem -LiteralPath "$($parameters.SCInstallRoot)" -Filter "*$Role.json").FullName
    jsonPathCustom          = (Get-ChildItem -LiteralPath "$($parameters.SCInstallRoot)/aws-custom" -Filter "*$Role.json").FullName
    CustomConfigurationFile = "$Role.json"
    LicenseFile             = "$($parameters.SCInstallRoot)\license.xml"
}

#endregion

$skip = @()

switch ($Role) {
    'DbResources' {
        $dbRoles = @(
            'Collection'
            'ReferenceData'
            'CortexProcessing'
            'CortexReporting'
            'CM'
            'Prc'
        )
        foreach ($dbRole in $dbRoles) {
            $local.SiteName = "$($parameters.prefix).$dbRole"
            $local.Package = (Get-ChildItem -LiteralPath "$($parameters.SCInstallRoot)" -Filter "*$DbRole.scwdp.zip").FullName
            $local.jsonPath = (Get-ChildItem -LiteralPath "$($parameters.SCInstallRoot)" -Filter "*$DbRole.json").FullName
            $appCmd = "C:\windows\system32\inetsrv\appcmd.exe"
            switch ($dbRole) {
                'Collection' {
                    $DeploymentParameters = @{
                        Package                        = $($local.Package)
                        XConnectCert                   = $($parameters.InstanceCertificateThumbPrint)
                        SiteName                       = $($local.SiteName)
                        SqlDbPrefix                    = $($parameters.prefix)
                        SqlServer                      = $($parameters.SQLServer)
                        SqlAdminUser                   = $($secrets.SqlAdminUser)
                        SqlAdminPassword               = $($secrets.SqlAdminPassword)
                        SqlCollectionUser              = $($secrets.SqlCollectionUser)
                        SqlCollectionPassword          = $($secrets.SqlCollectionPassword)
                        SqlProcessingPoolsUser         = $($secrets.SqlProcessingPoolsUser)
                        SqlProcessingPoolsPassword     = $($secrets.SqlProcessingPoolsPassword)
                        SqlMarketingAutomationUser     = $($secrets.SqlMarketingAutomationUser)
                        SqlMarketingAutomationPassword = $($secrets.SqlMarketingAutomationPassword)
                        SqlMessagingUser               = $($secrets.SqlMessagingUser)
                        SqlMessagingPassword           = $($secrets.SqlMessagingPassword)
                    }
                    $skip = @(
                        'SetAppPoolCertStorePermissions'
                        'StopWebsite'
                        'StopAppPool'
                        'RemoveDefaultBinding'
                        'CreateBindingsWithThumbprint'
                        'SetClientCertificatePermissions'
                        'SupportListManagerLargeUpload'
                        'CreateHostHeader'
                        'SetPermissions'
                        'SetLicense'
                        'CreateBindingsWithDevelopmentThumbprint'
                        'CleanShards'
                        'StartAppPool'
                        'StartWebsite'
                    )
                }
                'ReferenceData' {
                    $DeploymentParameters = @{
                        Package                  = $($local.Package)
                        LicenseFile              = $($local.LicenseFile)
                        SiteName                 = $($local.SiteName)
                        XConnectCert             = $($parameters.InstanceCertificateThumbPrint)
                        SqlDbPrefix              = $($parameters.prefix)
                        SqlServer                = $($parameters.SQLServer)
                        SqlAdminUser             = $($secrets.SqlAdminUser)
                        SqlAdminPassword         = $($secrets.SqlAdminPassword)
                        SqlReferenceDataUser     = $($secrets.SqlReferenceDataUser)
                        SqlReferenceDataPassword = $($secrets.SqlReferenceDataPassword)
                    }
                    $skip = @(
                        'SetAppPoolCertStorePermissions'
                        'StopWebsite'
                        'StopAppPool'
                        'RemoveDefaultBinding'
                        'CreateBindingsWithThumbprint'
                        'SetClientCertificatePermissions'
                        'CreateHostHeader'
                        'SetPermissions'
                        'SetLicense'
                        'CreateBindingsWithDevelopmentThumbprint'
                        'StartAppPool'
                        'StartWebsite'
                    )
                }
                'CortexProcessing' {
                    $DeploymentParameters = @{
                        Package                     = $($local.Package)
                        LicenseFile                 = $($local.LicenseFile)
                        SiteName                    = $($local.SiteName)
                        SSLCert                     = $($parameters.InstanceCertificateThumbPrint)
                        XConnectCert                = $($parameters.InstanceCertificateThumbPrint)
                        SqlDbPrefix                 = $($parameters.prefix)
                        SqlServer                   = $($parameters.SQLServer)
                        SqlAdminUser                = $($secrets.SqlAdminUser)
                        SqlAdminPassword            = $($secrets.SqlAdminPassword)
                        SqlMessagingUser            = $($secrets.SqlMessagingUser)
                        SqlMessagingPassword        = $($secrets.SqlMessagingPassword)
                        SqlProcessingEngineUser     = $($secrets.SqlProcessingEngineUser)
                        SqlProcessingEnginePassword = $($secrets.SqlProcessingEnginePassword)
                        SqlReportingUser            = $($secrets.SqlReportingUser)
                        SqlReportingPassword        = $($secrets.SqlReportingPassword)
                    }
                    $skip = @(
                        'SetAppPoolCertStorePermissions'
                        'StopWebsite'
                        'StopAppPool'
                        'RemoveDefaultBinding'
                        'CreateBindingsWithThumbprint'
                        'SetClientCertificatePermissions'
                        'CreateHostHeader'
                        'SetPermissions'
                        'SetLicense'
                        'CreateBindingsWithDevelopmentThumbprint'
                        'StartAppPool'
                        'StartWebsite'
                        'SetServicesCertStorePermissions'
                        'CreateServiceLogPath'
                        'SetProcessingEngineServiceLicense'
                        'SetServicePermissions'
                        'InstallService'
                        'StartService'
                    )
                }
                'CortexReporting' {
                    $DeploymentParameters = @{
                        Package              = $($local.Package)
                        LicenseFile          = $($local.LicenseFile)
                        SiteName             = $($local.SiteName)
                        SSLCert              = $($parameters.InstanceCertificateThumbPrint)
                        XConnectCert         = $($parameters.InstanceCertificateThumbPrint)
                        SqlDbPrefix          = $($parameters.prefix)
                        SqlServer            = $($parameters.SQLServer)
                        SqlAdminUser         = $($secrets.SqlAdminUser)
                        SqlAdminPassword     = $($secrets.SqlAdminPassword)
                        SqlReportingUser     = $($secrets.SqlReportingUser)
                        SqlReportingPassword = $($secrets.SqlReportingPassword)
                    }
                    $skip = @(
                        'SetAppPoolCertStorePermissions'
                        'StopWebsite'
                        'StopAppPool'
                        'RemoveDefaultBinding'
                        'CreateBindingsWithThumbprint'
                        'SetClientCertificatePermissions'
                        'CreateHostHeader'
                        'SetPermissions'
                        'SetLicense'
                        'CreateBindingsWithDevelopmentThumbprint'
                        'StartAppPool'
                        'StartWebsite'
                    )
                }
                'CM' {
                    $DeploymentParameters = @{
                        Package                  = $($local.Package)
                        LicenseFile              = $($local.LicenseFile)
                        SiteName                 = $($local.SiteName)
                        SSLCert                  = $($parameters.InstanceCertificateThumbPrint)
                        XConnectCert             = $($parameters.InstanceCertificateThumbPrint)
                        SqlDbPrefix              = $($parameters.prefix)
                        SqlServer                = $($parameters.SQLServer)
                        SqlAdminUser             = $($secrets.SqlAdminUser)
                        SqlAdminPassword         = $($secrets.SqlAdminPassword)
                        SqlCoreUser              = $($secrets.SqlCoreUser)
                        SqlCorePassword          = $($secrets.SqlCorePassword)
                        SqlSecurityUser          = $($secrets.SqlSecurityUser)
                        SqlSecurityPassword      = $($secrets.SqlSecurityPassword)
                        SqlMasterUser            = $($secrets.SqlMasterUser)
                        SqlMasterPassword        = $($secrets.SqlMasterPassword)
                        SqlWebUser               = $($secrets.SqlWebUser)
                        SqlWebPassword           = $($secrets.SqlWebPassword)
                        SqlReportingUser         = $($secrets.SqlReportingUser)
                        SqlReportingPassword     = $($secrets.SqlReportingPassword)
                        SqlReferenceDataUser     = $($secrets.SqlReferenceDataUser)
                        SqlReferenceDataPassword = $($secrets.SqlReferenceDataPassword)
                        SqlFormsUser             = $($secrets.SqlFormsUser)
                        SqlFormsPassword         = $($secrets.SqlFormsPassword)
                        SqlExmMasterUser         = $($secrets.SqlExmMasterUser)
                        SqlExmMasterPassword     = $($secrets.SqlExmMasterPassword)
                        SqlMessagingUser         = $($secrets.SqlMessagingUser)
                        SqlMessagingPassword     = $($secrets.SqlMessagingPassword)
                    }
                    $skip = @(
                        'StopWebsite'
                        'StopAppPool'
                        'RemoveDefaultBinding'
                        'CreateBindingsWithThumbprint'
                        'CreateHostHeader'
                        'SetPermissions'
                        'SetCertStorePermissions'
                        'SetLicense'
                        'CreateBindingsWithDevelopmentThumbprint'
                        'StartAppPool'
                        'StartWebsite'
                        'UpdateSolrSchema'
                    )
                }
                'Prc' {
                    $DeploymentParameters = @{
                        Package                    = $($local.Package)
                        LicenseFile                = $($local.LicenseFile)
                        SiteName                   = $($local.SiteName)
                        SSLCert                    = $($parameters.InstanceCertificateThumbPrint)
                        XConnectCert               = $($parameters.InstanceCertificateThumbPrint)
                        SqlDbPrefix                = $($parameters.prefix)
                        SqlServer                  = $($parameters.SQLServer)
                        SqlAdminUser               = $($secrets.SqlAdminUser)
                        SqlAdminPassword           = $($secrets.SqlAdminPassword)
                        SqlCoreUser                = $($secrets.SqlCoreUser)
                        SqlCorePassword            = $($secrets.SqlCorePassword)
                        SqlSecurityUser            = $($secrets.SqlSecurityUser)
                        SqlSecurityPassword        = $($secrets.SqlSecurityPassword)
                        SqlMasterUser              = $($secrets.SqlMasterUser)
                        SqlMasterPassword          = $($secrets.SqlMasterPassword)
                        SqlReportingUser           = $($secrets.SqlReportingUser)
                        SqlReportingPassword       = $($secrets.SqlReportingPassword)
                        SqlReferenceDataUser       = $($secrets.SqlReferenceDataUser)
                        SqlReferenceDataPassword   = $($secrets.SqlReferenceDataPassword)
                        SqlProcessingPoolsUser     = $($secrets.SqlProcessingPoolsUser)
                        SqlProcessingPoolsPassword = $($secrets.SqlProcessingPoolsPassword)
                        SqlProcessingTasksUser     = $($secrets.SqlProcessingTasksUser)
                        SqlProcessingTasksPassword = $($secrets.SqlProcessingTasksPassword)
                    }
                    $skip = @(
                        'StopWebsite'
                        'StopAppPool'
                        'RemoveDefaultBinding'
                        'CreateBindingsWithThumbprint'
                        'CreateHostHeader'
                        'SetPermissions'
                        'SetCertStorePermissions'
                        'SetLicense'
                        'CreateBindingsWithDevelopmentThumbprint'
                        'StartAppPool'
                        'StartWebsite'
                    )
                }
                Default { }
            }

            Push-Location $($parameters.SCInstallRoot)
            Install-SitecoreConfiguration @DeploymentParameters -Path $($local.jsonPath) -Skip $skip -Verbose *>&1 | Tee-Object "$DbRole.log"
            & $appcmd delete site $($local.SiteName)
            & $appcmd delete apppool$($local.SiteName)
            Pop-Location
        }
    }
    'IdentityServer' {
        $DeploymentParameters = @{
            Package                 = $($local.Package)
            SitecoreIdentityCert    = $($parameters.InstanceCertificateThumbPrint)
            LicenseFile             = $($local.LicenseFile)
            SiteName                = $($local.SiteName)
            PasswordRecoveryUrl     = $($parameters.PasswordRecoveryUrl)
            AllowedCorsOrigins      = $($parameters.allowedCorsOrigins)
            ClientSecret            = $($secrets.ClientSecret)
            CustomConfigurationFile = $($local.CustomConfigurationFile)
            DnsName                 = $($parameters.IdentityServerDNS)
            SqlServer               = $($parameters.SQLServer)
            SqlDbPrefix             = $($parameters.prefix)
            SqlSecurityUser         = $($secrets.SqlSecurityUser)
            SqlSecurityPassword     = $($secrets.SqlSecurityPassword)
        }
    }
    'Collection' {
        $DeploymentParameters = @{
            Package                        = $($local.Package)
            LicenseFile                    = $($local.LicenseFile)
            SiteName                       = $($local.SiteName)
            SSLCert                        = $($parameters.InstanceCertificateThumbPrint)
            XConnectCert                   = $($parameters.InstanceCertificateThumbPrint)
            XConnectEnvironment            = $($parameters.Environment)
            XConnectLogLevel               = $($parameters.LogLevel)
            DnsName                        = $($parameters.CollectionDNS)
            SqlDbPrefix                    = $($parameters.prefix)
            SqlServer                      = $($parameters.SQLServer)
            SqlAdminUser                   = $($secrets.SqlAdminUser)
            SqlAdminPassword               = $($secrets.SqlAdminPassword)
            SqlCollectionUser              = $($secrets.SqlCollectionUser)
            SqlCollectionPassword          = $($secrets.SqlCollectionPassword)
            SqlProcessingPoolsUser         = $($secrets.SqlProcessingPoolsUser)
            SqlProcessingPoolsPassword     = $($secrets.SqlProcessingPoolsPassword)
            SqlMarketingAutomationUser     = $($secrets.SqlMarketingAutomationUser)
            SqlMarketingAutomationPassword = $($secrets.SqlMarketingAutomationPassword)
            SqlMessagingUser               = $($secrets.SqlMessagingUser)
            SqlMessagingPassword           = $($secrets.SqlMessagingPassword)
        }
        $skip = @(
            'CreateShards'
            'CleanShards'
            'CreateShardApplicationDatabaseServerLoginSqlCmd'
            'CreateShardManagerApplicationDatabaseUserSqlCmd'
            'CreateShard0ApplicationDatabaseUserSqlCmd'
            'CreateShard1ApplicationDatabaseUserSqlCmd'
        )
    }
    'CollectionSearch' {
        $DeploymentParameters = @{
            Package                        = $($local.Package)
            LicenseFile                    = $($local.LicenseFile)
            SiteName                       = $($local.SiteName)
            SSLCert                        = $($parameters.InstanceCertificateThumbPrint)
            XConnectCert                   = $($parameters.InstanceCertificateThumbPrint)
            SolrCorePrefix                 = $($parameters.SolrCorePrefix)
            SolrUrl                        = $($parameters.SolrUrl)
            XConnectEnvironment            = $($parameters.Environment)
            XConnectLogLevel               = $($parameters.LogLevel)
            DnsName                        = $($parameters.CollectionSearchDNS)
            SqlDbPrefix                    = $($parameters.prefix)
            SqlServer                      = $($parameters.SQLServer)
            SqlCollectionUser              = $($secrets.SqlCollectionUser)
            SqlCollectionPassword          = $($secrets.SqlCollectionPassword)
            SqlProcessingPoolsUser         = $($secrets.SqlProcessingPoolsUser)
            SqlProcessingPoolsPassword     = $($secrets.SqlProcessingPoolsPassword)
            SqlMarketingAutomationUser     = $($secrets.SqlMarketingAutomationUser)
            SqlMarketingAutomationPassword = $($secrets.SqlMarketingAutomationPassword)
            SqlMessagingUser               = $($secrets.SqlMessagingUser)
            SqlMessagingPassword           = $($secrets.SqlMessagingPassword)
        }
    }
    'ReferenceData' {
        $DeploymentParameters = @{
            Package                  = $($local.Package)
            LicenseFile              = $($local.LicenseFile)
            SiteName                 = $($local.SiteName)
            XConnectCert             = $($parameters.InstanceCertificateThumbPrint)
            XConnectEnvironment      = $($parameters.Environment)
            XConnectLogLevel         = $($parameters.LogLevel)
            DnsName                  = $($parameters.ReferenceDataDNS)
            SqlDbPrefix              = $($parameters.prefix)
            SqlServer                = $($parameters.SQLServer)
            SqlAdminUser             = $($secrets.SqlAdminUser)
            SqlAdminPassword         = $($secrets.SqlAdminPassword)
            SqlReferenceDataUser     = $($secrets.SqlReferenceDataUser)
            SqlReferenceDataPassword = $($secrets.SqlReferenceDataPassword)
        }
    }
    'MarketingAutomation' {
        $DeploymentParameters = @{
            Package                         = $($local.Package)
            LicenseFile                     = $($local.LicenseFile)
            SiteName                        = $($local.SiteName)
            SSLCert                         = $($parameters.InstanceCertificateThumbPrint)
            XConnectCert                    = $($parameters.InstanceCertificateThumbPrint)
            XConnectCollectionSearchService = $($parameters.XConnectCollectionSearchService)
            XConnectReferenceDataService    = $($parameters.XConnectReferenceDataService)
            XConnectEnvironment             = $($parameters.Environment)
            XConnectLogLevel                = $($parameters.LogLevel)
            DnsName                         = $($parameters.MarketingAutomationDNS)
            SqlServer                       = $($parameters.SQLServer)
            SqlDbPrefix                     = $($parameters.prefix)
            SqlAdminUser                    = $($secrets.SqlAdminUser)
            SqlAdminPassword                = $($secrets.SqlAdminPassword)
            SqlCollectionUser               = $($secrets.SqlCollectionUser)
            SqlCollectionPassword           = $($secrets.SqlCollectionPassword)
            SqlProcessingPoolsUser          = $($secrets.SqlProcessingPoolsUser)
            SqlProcessingPoolsPassword      = $($secrets.SqlProcessingPoolsPassword)
            SqlReferenceDataUser            = $($secrets.SqlReferenceDataUser)
            SqlReferenceDataPassword        = $($secrets.SqlReferenceDataPassword)
            SqlMarketingAutomationUser      = $($secrets.SqlMarketingAutomationUser)
            SqlMarketingAutomationPassword  = $($secrets.SqlMarketingAutomationPassword)
            SqlMessagingUser                = $($secrets.SqlMessagingUser)
            SqlMessagingPassword            = $($secrets.SqlMessagingPassword)

        }
    }
    'MarketingAutomationReporting' {
        $DeploymentParameters = @{
            Package                        = $($local.Package)
            LicenseFile                    = $($local.LicenseFile)
            SiteName                       = $($local.SiteName)
            SSLCert                        = $($parameters.InstanceCertificateThumbPrint)
            XConnectCert                   = $($parameters.InstanceCertificateThumbPrint)
            XConnectEnvironment            = $($parameters.Environment)
            XConnectLogLevel               = $($parameters.LogLevel)
            DnsName                        = $($parameters.MarketingAutomationReportingDNS)
            SqlDbPrefix                    = $($parameters.prefix)
            SqlServer                      = $($parameters.SQLServer)
            SqlReferenceDataUser           = $($secrets.SqlReferenceDataUser)
            SqlReferenceDataPassword       = $($secrets.SqlReferenceDataPassword)
            SqlMarketingAutomationUser     = $($secrets.SqlMarketingAutomationUser)
            SqlMarketingAutomationPassword = $($secrets.SqlMarketingAutomationPassword)
        }
    }
    'CortexProcessing' {
        $DeploymentParameters = @{
            Package                     = $($local.Package)
            LicenseFile                 = $($local.LicenseFile)
            SiteName                    = $($local.SiteName)
            SSLCert                     = $($parameters.InstanceCertificateThumbPrint)
            XConnectCert                = $($parameters.InstanceCertificateThumbPrint)
            XConnectCollectionService   = $($parameters.XConnectCollectionService)
            XConnectSearchService       = $($parameters.XConnectSearchService)
            XConnectEnvironment         = $($parameters.Environment)
            XConnectLogLevel            = $($parameters.LogLevel)
            DnsName                     = $($parameters.CortexProcessingDNS)
            SqlDbPrefix                 = $($parameters.prefix)
            SqlServer                   = $($parameters.SQLServer)
            SqlAdminUser                = $($secrets.SqlAdminUser)
            SqlAdminPassword            = $($secrets.SqlAdminPassword)
            SqlMessagingUser            = $($secrets.SqlMessagingUser)
            SqlMessagingPassword        = $($secrets.SqlMessagingPassword)
            SqlProcessingEngineUser     = $($secrets.SqlProcessingEngineUser)
            SqlProcessingEnginePassword = $($secrets.SqlProcessingEnginePassword)
            SqlReportingUser            = $($secrets.SqlReportingUser)
            SqlReportingPassword        = $($secrets.SqlReportingPassword)
        }
    }
    'CortexReporting' {
        $DeploymentParameters = @{
            Package              = $($local.Package)
            LicenseFile          = $($local.LicenseFile)
            SiteName             = $($local.SiteName)
            SSLCert              = $($parameters.InstanceCertificateThumbPrint)
            XConnectCert         = $($parameters.InstanceCertificateThumbPrint)
            XConnectEnvironment  = $($parameters.Environment)
            XConnectLogLevel     = $($parameters.LogLevel)
            DnsName              = $($parameters.CortexReportingDNS)
            SqlDbPrefix          = $($parameters.prefix)
            SqlServer            = $($parameters.SQLServer)
            SqlAdminUser         = $($secrets.SqlAdminUser)
            SqlAdminPassword     = $($secrets.SqlAdminPassword)
            SqlReportingUser     = $($secrets.SqlReportingUser)
            SqlReportingPassword = $($secrets.SqlReportingPassword)
        }
    }
    'CM' {
        $DeploymentParameters = @{
            Package                              = $($local.Package)
            LicenseFile                          = $($local.LicenseFile)
            SiteName                             = $($local.SiteName)
            SitecoreAdminPassword                = $($secrets.SitecoreAdminPassword)
            SSLCert                              = $($parameters.InstanceCertificateThumbPrint)
            XConnectCert                         = $($parameters.InstanceCertificateThumbPrint)
            SolrUrl                              = $($parameters.SolrUrl)
            SitecoreIdentityAuthority            = $($parameters.SitecoreIdentityAuthority)
            SitecoreIdentitySecret               = $($secrets.SitecoreIdentitySecret)
            XConnectCollectionSearchService      = $($parameters.XConnectCollectionSearchService)
            XConnectReferenceDataService         = $($parameters.XConnectReferenceDataService)
            MarketingAutomationOperationsService = $($parameters.MarketingAutomationOperationsService)
            MarketingAutomationReportingService  = $($parameters.MarketingAutomationReportingService)
            CortexReportingService               = $($parameters.CortexReportingService)
            ProcessingService                    = $($parameters.ProcessingService)
            ReportingService                     = $($parameters.ReportingService)
            ReportingServiceApiKey               = $($secrets.ReportingServiceApiKey)
            DnsName                              = $($parameters.CMDNS)
            SqlDbPrefix                          = $($parameters.prefix)
            SqlServer                            = $($parameters.SQLServer)
            SqlAdminUser                         = $($secrets.SqlAdminUser)
            SqlAdminPassword                     = $($secrets.SqlAdminPassword)
            SqlCoreUser                          = $($secrets.SqlCoreUser)
            SqlCorePassword                      = $($secrets.SqlCorePassword)
            SqlSecurityUser                      = $($secrets.SqlSecurityUser)
            SqlSecurityPassword                  = $($secrets.SqlSecurityPassword)
            SqlMasterUser                        = $($secrets.SqlMasterUser)
            SqlMasterPassword                    = $($secrets.SqlMasterPassword)
            SqlWebUser                           = $($secrets.SqlWebUser)
            SqlWebPassword                       = $($secrets.SqlWebPassword)
            SqlReportingUser                     = $($secrets.SqlReportingUser)
            SqlReportingPassword                 = $($secrets.SqlReportingPassword)
            SqlReferenceDataUser                 = $($secrets.SqlReferenceDataUser)
            SqlReferenceDataPassword             = $($secrets.SqlReferenceDataPassword)
            SqlFormsUser                         = $($secrets.SqlFormsUser)
            SqlFormsPassword                     = $($secrets.SqlFormsPassword)
            SqlExmMasterUser                     = $($secrets.SqlExmMasterUser)
            SqlExmMasterPassword                 = $($secrets.SqlExmMasterPassword)
            SqlMessagingUser                     = $($secrets.SqlMessagingUser)
            SqlMessagingPassword                 = $($secrets.SqlMessagingPassword)
        }
    }
    'CD' {
        $DeploymentParameters = @{
            Package                              = $($local.Package)
            LicenseFile                          = $($local.LicenseFile)
            SiteName                             = $($local.SiteName)
            XConnectCert                         = $($parameters.InstanceCertificateThumbPrint)
            SolrUrl                              = $($parameters.SolrUrl)
            SolrCorePrefix                       = $($parameters.SolrCorePrefix)
            SitecoreIdentityAuthority            = $($parameters.SitecoreIdentityAuthority)
            XConnectCollectionService            = $($parameters.XConnectCollectionService)
            XConnectReferenceDataService         = $($parameters.XConnectReferenceDataService)
            MarketingAutomationOperationsService = $($parameters.MarketingAutomationOperationsService)
            MarketingAutomationReportingService  = $($parameters.MarketingAutomationReportingService)
            DnsName                              = $($parameters.CDDNS)
            SqlDbPrefix                          = $($parameters.prefix)
            SqlServer                            = $($parameters.SQLServer)
            SqlSecurityUser                      = $($secrets.SqlSecurityUser)
            SqlSecurityPassword                  = $($secrets.SqlSecurityPassword)
            SqlWebUser                           = $($secrets.SqlWebUser)
            SqlWebPassword                       = $($secrets.SqlWebPassword)
            SqlFormsUser                         = $($secrets.SqlFormsUser)
            SqlFormsPassword                     = $($secrets.SqlFormsPassword)
            SqlExmMasterUser                     = $($secrets.SqlExmMasterUser)
            SqlExmMasterPassword                 = $($secrets.SqlExmMasterPassword)
            SqlMessagingUser                     = $($secrets.SqlMessagingUser)
            SqlMessagingPassword                 = $($secrets.SqlMessagingPassword)
        }
    }
    'Prc' {
        $DeploymentParameters = @{
            Package                    = $($local.Package)
            LicenseFile                = $($local.LicenseFile)
            SiteName                   = $($local.SiteName)
            SSLCert                    = $($parameters.InstanceCertificateThumbPrint)
            XConnectCert               = $($parameters.InstanceCertificateThumbPrint)
            XConnectCollectionService  = $($parameters.XConnectCollectionService)
            ReportingServiceApiKey     = $($secrets.ReportingServiceApiKey)
            DnsName                    = $($parameters.PrcDNS)
            SqlDbPrefix                = $($parameters.prefix)
            SqlServer                  = $($parameters.SQLServer)
            SqlAdminUser               = $($secrets.SqlAdminUser)
            SqlAdminPassword           = $($secrets.SqlAdminPassword)
            SqlCoreUser                = $($secrets.SqlCoreUser)
            SqlCorePassword            = $($secrets.SqlCorePassword)
            SqlSecurityUser            = $($secrets.SqlSecurityUser)
            SqlSecurityPassword        = $($secrets.SqlSecurityPassword)
            SqlMasterUser              = $($secrets.SqlMasterUser)
            SqlMasterPassword          = $($secrets.SqlMasterPassword)
            SqlReportingUser           = $($secrets.SqlReportingUser)
            SqlReportingPassword       = $($secrets.SqlReportingPassword)
            SqlReferenceDataUser       = $($secrets.SqlReferenceDataUser)
            SqlReferenceDataPassword   = $($secrets.SqlReferenceDataPassword)
            SqlProcessingPoolsUser     = $($secrets.SqlProcessingPoolsUser)
            SqlProcessingPoolsPassword = $($secrets.SqlProcessingPoolsPassword)
            SqlProcessingTasksUser     = $($secrets.SqlProcessingTasksUser)
            SqlProcessingTasksPassword = $($secrets.SqlProcessingTasksPassword)
        }
    }
    'Rep' {
        $DeploymentParameters = @{
            Package                = $($local.Package)
            LicenseFile            = $($local.LicenseFile)
            SiteName               = $($local.SiteName)
            SSLCert                = $($parameters.InstanceCertificateThumbPrint)
            ReportingServiceApiKey = $($secrets.ReportingServiceApiKey)
            DnsName                = $($parameters.RepDNS)
            SqlDbPrefix            = $($parameters.prefix)
            SqlServer              = $($parameters.SQLServer)
            SqlCoreUser            = $($secrets.SqlCoreUser)
            SqlCorePassword        = $($secrets.SqlCorePassword)
            SqlSecurityUser        = $($secrets.SqlSecurityUser)
            SqlSecurityPassword    = $($secrets.SqlSecurityPassword)
            SqlMasterUser          = $($secrets.SqlMasterUser)
            SqlMasterPassword      = $($secrets.SqlMasterPassword)
            SqlReportingUser       = $($secrets.SqlReportingUser)
            SqlReportingPassword   = $($secrets.SqlReportingPassword)
        }
    }
}

If ($Role -ne 'DbResources') {
    Push-Location $($parameters.SCInstallRoot)
    Install-SitecoreConfiguration @DeploymentParameters -Path $($local.jsonPathCustom) -Skip $skip -Verbose *>&1 | Tee-Object "$Role.log"
    Pop-Location
}