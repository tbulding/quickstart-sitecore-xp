# quickstart-quickstart-sitecore-xp

This Quick Start deploys a full sitecore stack on AWS. The deployment consists of 12 sitecore roles (EC2 Instrances), SQL Server (RDS), Redis (ElastiCache)
You can choose to deploy sitecore into your existing VPC or create a New VPC.

Deployment Steps:

1. Sign up for an AWS account at https://aws.amazon.com, select a region, and create a key pair.
2. In the AWS CloudFormation console, launch one of the following templates to build the new stack:

/templates/sitecore-xp-master.template.yaml
/templates/sitecore-xp-existing-vpc.template.yaml

3. 

Pre-reqs:

1) Signup with Sitecore here : https://profile.sitecore.net/en/SignUp/Signup.aspx
2) Download the files here: 
https://dev.sitecore.net/Downloads/Sitecore_Experience_Platform/93/Sitecore_Experience_Platform_93_Initial_Release.aspx

3) Download the Sitecore 9.3.0 XP1 (Scaled) installation files located under “Download options for On Premises deployment”
•	This downloaded ZIP will contain around 15 Zip files.
•	Extract the downloaded ZIP to a location on your workstation. Do NOT unzip the additional zip files

4) If you dont already have a sitecore license file, request a developer one here:
https://www.sitecore.com/knowledge-center/getting-started/developer-trial

5) Either have or create a DNS name for the sitecore installation. 
•	You will need to provide DNS hostnames for the CD, CM and IS roles
6) Create a certificate for the above DNS name in ACM. The best suggestion would be to use a wildcard certificate name for the cert. E.g: *.yourdomain.com
Once created and approved, make note of the certificates ARN

7) Create a bucket in S3 where you will store the these extracted files. This should be in the same account where the QS is being deployed
•	This same bucket will be used to upload resources during the Sitecore Quick Start deployemnt
8) In the bucket, create a prefix (Folder). In the Quick Start this prefix example name is resources
Create another prefix called license

9) Upload the Sitecore installation files (The extracted Zip contents) to the resources prefix in your bucket
10) Upload the License zip file to the license prefix in your bucket

11) Clone the quickstart-sitecore -xp repo to your local workstation
12) Either in the existing bucket, or in a new one, create a prefix called quickstart-sitecore-xp
13) Upload the cloned repo contents to this prefix.
•	The prefix will then contain some folders, including ci, functions, scripts, submodules, templates
14) Open up the templates prefix, and select ‘ sitecore-xp-master.template.yaml ’. Copy the Object URL

15) Open up the CloudFormation console. When creating the new stack, past the Object URL in the Amazon S3 URL field

16) Fill in the parameters for the deployment. The list below are some of the parameters which are explicitly called out for the installation:
•	‘External Amazon Certificate Manager ARN’ - this is the ARN from step 6
•	DNS name for Content Delivery Role - name.exampledomain.com
•	DNS name for Content Management Role - namecm.exampledomain.com
•	DNS name for Identity Server Role - nameis.exampledomain.com
•	The Prefix to be used for the Sitecore installation - this can be any prefix. E.g: sc93
•	S3 Bucket where Sitecore artifacts are located (Resource files, licence files.) - The bucket name created in step 7
•	The prefix where Sitecore installation files are located (eg: sitecorefiles/) - The prefix created in step 8
•	The prefix where the sitecore license.zip is located (eg: licence/) - The prefix created in step 8 for the license file
•	The prefix used for the SOLR Cores - If you have an existing Solr deployment with preconfigured cores, provide the core prefix here, else provide a prefix for the cores which will be created in the developer deployment of solr
•	The Url for the SOLR deployment - if not provided, a development solr cluster will be installed
•	The Sitecore Cors Origins - this can be set to *
•	The email address for receiving notifications on instance scaling. - your email address for notifications
•	Quick Start S3 bucket name - the bucket name used in step 12
•	Quick Start S3 key prefix - the prefix created in step 12

Once deployed, you can get the DNS name for the external facing Load Balancer.
The 3 provided names for Content Delivery, Management and Identity will need to be created as CNAMEs and set to point to the URL of the external facing load balancer
