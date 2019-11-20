# quickstart-quickstart-sitecore-xp

This Quick Start deploys a full sitecore stack on AWS. The deployment consists of 12 sitecore roles (EC2 Instrances), SQL Server (RDS), Redis (ElastiCache)
You can choose to deploy sitecore into your existing VPC or create a New VPC.

Deployment Steps:

1. Sign up for an AWS account at https://aws.amazon.com, select a region, and create a key pair.
2. In the AWS CloudFormation console, launch one of the following templates to build the new stack:

/templates/sitecore-xp-master.template.yaml
/templates/sitecore-xp-existing-vpc.template.yaml

3. 