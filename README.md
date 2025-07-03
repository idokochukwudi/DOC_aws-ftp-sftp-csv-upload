## Project: Provision EC2 or AWS Transfer for SFTP CSV Upload (Spike)


### Project Overview:

Provision EC2 instance or AWS Transfer Family SFTP server for secure CSV file uploads using Terraform with modular design and GitHub Actions CI/CD.

---

### FILE STRUCTURE

```
 terraform/
 ├── main.tf
 ├── variables.tf
 ├── outputs.tf
 ├── terraform.tfvars
 ├── README.md
 ├── .github/
 │   └── workflows/
 │       └── terraform.yml
 ├── scripts/
 │   └── install-vsftpd.sh
 └── modules/
     ├── network/
     │   ├── main.tf
     │   ├── variables.tf
     │   └── outputs.tf
     ├── ec2_sftp/
     │   ├── main.tf
     │   ├── variables.tf
     │   └── outputs.tf
     └── aws_transfer_sftp/
         ├── main.tf
         ├── variables.tf
         └── outputs.tf
```

---

### Step 0: Prerequisites and Setup

**Purpose:**

- Prepare environment with AWS CLI, Terraform, AWS credentials, and SSH key pair for EC2 access.

**What I did:**

- Configured AWS CLI locally with proper credentials.
- Installed Terraform on my machine.
- Stored AWS credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY) securely as GitHub Secrets.
- Created SSH key pair using AWS CLI to enable SSH access to EC2 instances.

**Command:**

```bash
aws ec2 create-key-pair --key-name ftp-key --query 'KeyMaterial' --output text --region us-east-1 > ftp-key.pem
chmod 400 ftp-key.pem
```

![](./img/1.keypair-generate.png)

---

### Step 1: Create Bootstrap Script (install-vsftpd.sh)

**Purpose:**

- Install and configure `vsftpd` FTP server on EC2 instance automatically on launch.

**What I did:**
- Wrote shell script to update apt packages, install `vsftpd`, configure for secure FTP (**disable anonymous, enable local users and write**), and **enable service**.

**Content:**

```bash
#!/bin/bash
apt-get update -y
apt-get install -y vsftpd

cp /etc/vsftpd.conf /etc/vsftpd.conf.bak
sed -i 's/anonymous_enable=YES/anonymous_enable=NO/' /etc/vsftpd.conf
sed -i 's/#local_enable=YES/local_enable=YES/' /etc/vsftpd.conf
sed -i 's/#write_enable=YES/write_enable=YES/' /etc/vsftpd.conf

systemctl restart vsftpd
systemctl enable vsftpd
```

---

### Step 2: Define Network Module (`modules/network`)

**Purpose:**

- Provision dedicated `VPC` and `subnet` for hosting `EC2` and **Transfer Family services**.

**What I did:**

- Created `aws_vpc` resource with CIDR block `10.0.0.0/16`.
- Created a `subnet` in the first availability zone with CIDR block `10.0.1.0/24`.
- Output the `VPC` and `subnet IDs` for reuse.

### modules/network/main.tf

```bash
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name = "ftp-vpc"
  }
}

data "aws_availability_zones" "available" {}

resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name = "ftp-subnet"
  }
}
```

### modules/network/outputs.tf

```bash
output "vpc_id" {
  value = aws_vpc.main.id
  description = "ID of the main VPC"
}

output "subnet_id" {
  value = aws_subnet.public.id
  description = "ID of the public subnet"
}
```
---

### Step 3: Define EC2 SFTP Module (`modules/ec2_sftp`)

**Purpose:**

- Provision EC2 instance with `vsftpd` installed to simulate FTP server for CSV upload.

**What I did:**

- Used Ubuntu 20.04 AMI data source for latest AMI.
- Created a security group allowing TCP port 21 inbound from allowed IPs.
- Provisioned EC2 instance with `user_data` to run **bootstrap script**.
- Tagged resources for easy identification.
- Output EC2 public IP for access.

### modules/ec2_sftp/main.tf

```bash
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }
}

resource "aws_security_group" "ftp_sg" {
  name        = "ftp-sg"
  description = "Allow FTP access"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 21
    to_port     = 21
    protocol    = "tcp"
    cidr_blocks = var.allowed_ips
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "ftp_server" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name               = var.key_name
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.ftp_sg.id]
  user_data              = file("${path.module}/../../scripts/install-vsftpd.sh")

  tags = {
    Name = "ftp-server"
  }
}
```

### modules/ec2_sftp/variables.tf

```hcl
# IAM user and GitHub integration
variable "iam_user_name" {
  description = "Name of the IAM user to create and manage"
  type        = string
}

variable "github_repo" {
  description = "GitHub repository name where secrets will be stored"
  type        = string
}

# S3 buckets for clean and raw data
variable "clean_data_name" {
  description = "S3 bucket name for clean data"
  type        = string
}

variable "github_user_name" {
  description = "GitHub username for IAM user policy integration"
  type        = string
}


variable "raw_data_name" {
  description = "S3 bucket name for raw data"
  type        = string
}

variable "sse_algorithm" {
  description = "Server-side encryption algorithm to use (e.g., aws:kms)"
  type        = string
}

variable "env" {
  description = "Environment (e.g., dev, staging, prod)"
  type        = string
}

# EC2 and networking
variable "instance_type" {
  description = "EC2 instance type for the SFTP server"
  type        = string
}

variable "key_name" {
  description = "SSH key pair name to attach to EC2 instance"
  type        = string
}

variable "allowed_ips" {
  description = "List of allowed CIDR IPs for accessing EC2 instance"
  type        = list(string)
}

# AWS Transfer Family (SFTP)
variable "iam_role_name" {
  description = "IAM role name used by AWS Transfer Family for SFTP access"
  type        = string
}

variable "s3_transfer_bucket" {
  description = "S3 bucket used by AWS Transfer Family to store files"
  type        = string
}

# Bucket names to reference in policy
variable "clean_data_bucket" {
  description = "S3 bucket name for clean data used in IAM policy"
  type        = string
}

variable "raw_data_bucket" {
  description = "S3 bucket name for raw data used in IAM policy"
  type        = string
}
```

### modules/ec2_sftp/outputs.tf

```bash
output "public_ip" {
  value       = aws_instance.ftp_server.public_ip
  description = "Public IP address of the EC2 SFTP instance"
}
```

---

### Step 4: Define AWS Transfer Family Module (`modules/aws_transfer_sftp`)

**Purpose:**

- Create AWS **Transfer Family SFTP server** for modern, managed `SFTP` file upload to `S3`.

**What I did:**

- Created IAM role with assume role policy for `transfer.amazonaws.com` service.
- Attached inline policy granting full S3 access to specified bucket.
- Created Transfer Family SFTP server using service managed identity provider.
- Output the public endpoint of the server.

### modules/aws_transfer_sftp/main.tf

```bash
resource "aws_iam_role" "transfer_role" {
  name = var.iam_role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "transfer.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "s3_access" {
  name = "S3TransferAccess"
  role = aws_iam_role.transfer_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = ["s3:*"],
      Resource = [
        "arn:aws:s3:::${var.s3_bucket}",
        "arn:aws:s3:::${var.s3_bucket}/*"
      ]
    }]
  })
}

resource "aws_transfer_server" "sftp_server" {
  identity_provider_type = "SERVICE_MANAGED"
  endpoint_type          = "PUBLIC"
  logging_role           = aws_iam_role.transfer_role.arn

  tags = {
    Name = "TransferFamilySFTP"
  }
}
```

### modules/aws_transfer_sftp/variables.tf

```bash
variable "iam_role_name" {
  description = "Name of the IAM role used by Transfer Family"
  type        = string
}

variable "s3_bucket" {
  description = "S3 bucket name for file storage"
  type        = string
}
```

### modules/aws_transfer_sftp/outputs.tf

```hcl
output "endpoint" {
  value       = aws_transfer_server.sftp_server.endpoint
  description = "Public endpoint of the AWS Transfer Family SFTP server"
}
```

---

### Step 5: Integrate IAM User Policy Module

**Purpose:**

- Attach required policies to existing GitHub user `github-actions-user` for `S3` access.

**What I did:**

- Pulled external terraform module "`iam_user_policy`" from **GitHub feature branch**.
- Passed GitHub username and S3 bucket names as variables.
- Let module handle creation and attachment of policies.

### Root `main.tf` snippet to call module

```hcl
# Call IAM module and push credentials to GitHub Secrets.
module "github_iam_user" {
  source        = "./modules/aws_iam_user"
  iam_user_name = var.iam_user_name
  }

# Store AWS Access Key ID in GitHub repository secrets
resource "github_actions_secret" "aws_access_key_id" {
  repository      = var.github_repo
  secret_name     = "AWS_ACCESS_KEY_ID"
  plaintext_value = module.github_iam_user.access_key_id
}

# Store AWS Secret Access Key in GitHub repository secrets
resource "github_actions_secret" "aws_secret_access_key" {
  repository      = var.github_repo
  secret_name     = "AWS_SECRET_ACCESS_KEY"
  plaintext_value = module.github_iam_user.secret_access_key
}

####################################################################
# Project: Provision EC2 or AWS Transfer for SFTP CSV Upload (Spike)
####################################################################


module "network" {
  source = "./modules/network"
}

module "ec2_sftp" {
  source        = "./modules/ec2_sftp"
  instance_type = var.instance_type
  key_name      = var.key_name
  vpc_id        = module.network.vpc_id
  subnet_id     = module.network.subnet_id
  allowed_ips   = var.allowed_ips
}

module "aws_transfer_sftp" {
  source       = "./modules/aws_transfer_sftp"
  iam_role_name = var.iam_role_name
  s3_bucket    = var.s3_transfer_bucket
}

module "iam_user_policy_sftp_csv_upload" {
  source         = "./modules/iam_user_policy_sftp_csv_upload"
  policy_name    = "S3AccessPolicyForCSVUpload"
  iam_user_name  = var.iam_user_name
  description    = "Policy to allow S3 access for CSV upload"

  policy_statements = [
    {
      Sid    = "AllowS3FullAccess"
      Effect = "Allow"
      Action = "s3:*"
      Resource = [
        "arn:aws:s3:::${var.clean_data_bucket}",
        "arn:aws:s3:::${var.clean_data_bucket}/*",
        "arn:aws:s3:::${var.raw_data_bucket}",
        "arn:aws:s3:::${var.raw_data_bucket}/*"
      ]
    }
  ]
}
```

---

### Step 6: Create Root Terraform Configuration

**Purpose:**

- Tie all modules together with proper input variables.

**What I did:**

- Called `network`, `ec2_sftp`, `aws_transfer_sftp`, and `iam_user_policy` modules.
- Passed variables via `terraform.tfvars`.
- Defined outputs to display `EC2 IP` and `Transfer Family endpoint`.

### Root `main.tf`

```hcl
module "network" {
  source = "./modules/network"
}

module "ec2_sftp" {
  source        = "./modules/ec2_sftp"
  instance_type = var.instance_type
  key_name      = var.key_name
  vpc_id        = module.network.vpc_id
  subnet_id     = module.network.subnet_id
  allowed_ips   = var.allowed_ips
}

module "aws_transfer_sftp" {
  source       = "./modules/aws_transfer_sftp"
  iam_role_name = var.iam_role_name
  s3_bucket    = var.s3_transfer_bucket
}

module "iam_user_policy" {
  source          = "git::https://github.com/xterns/pulsegrid-etl-xpod-06-25.git//terraform/modules/iam_user_policy?ref=feature/understand-python-role-data-processing"
  github_user     = var.github_user_name
  s3_clean_bucket = var.s3_bucket
  s3_raw_bucket   = var.raw_bucket
}
```

### Root `variables.tf`

```hcl
# IAM user and GitHub integration
variable "iam_user_name" {
  description = "Name of the IAM user to create and manage"
  type        = string
}

# S3 buckets for clean and raw data
variable "clean_data_name" {
  description = "S3 bucket name for clean data"
  type        = string
}

variable "raw_data_name" {
  description = "S3 bucket name for raw data"
  type        = string
}

variable "sse_algorithm" {
  description = "Server-side encryption algorithm to use (e.g., aws:kms)"
  type        = string
}

variable "env" {
  description = "Environment (e.g., dev, staging, prod)"
  type        = string
}

# EC2 and networking
variable "instance_type" {
  description = "EC2 instance type for the SFTP server"
  type        = string
}

variable "key_name" {
  description = "SSH key pair name to attach to EC2 instance"
  type        = string
}

variable "allowed_ips" {
  description = "List of allowed CIDR IPs for accessing EC2 instance"
  type        = list(string)
}

# AWS Transfer Family (SFTP)
variable "iam_role_name" {
  description = "IAM role name used by AWS Transfer Family for SFTP access"
  type        = string
}

variable "s3_transfer_bucket" {
  description = "S3 bucket used by AWS Transfer Family to store files"
  type        = string
}

# Bucket names to reference in policy
variable "clean_data_bucket" {
  description = "S3 bucket name for clean data used in IAM policy"
  type        = string
}

variable "raw_data_bucket" {
  description = "S3 bucket name for raw data used in IAM policy"
  type        = string
}

variable "github_repo" {
  description = "GitHub repository name"
  type        = string
  default     = "pulsegrid-etl-xpod-06-25"
}

variable "github_owner" {
  description = "GitHub username or organization"
  type        = string
  default     = "xterns"
}

variable "github_token" {
  description = "GitHub personal access token"
  type        = string
  sensitive   = true
}
```

### Root `outputs.tf`

```hcl
output "ec2_public_ip" {
  value       = module.ec2_sftp.public_ip
  description = "Public IP of the EC2 FTP server"
}

output "transfer_endpoint" {
  value       = module.aws_transfer_sftp.endpoint
  description = "AWS Transfer Family SFTP endpoint"
}
```

---

### Step 7: Define Variables and tfvars

**Purpose:**

- Define inputs for modular and root terraform configurations.

**What I did:**

- Declared variables such as `github_user_name`, `s3_bucket`, `raw_bucket`, `key_name`, `instance_type`, `allowed_ips`, `iam_role_name`, and `s3_transfer_bucket`.
- Provided environment-specific values in `terraform.tfvars`.

### Root `terraform.tfvars`

```hcl
secret
```

---

### Step 8: Setup GitHub Actions Workflow

**Purpose:**

- Automate `Terraform init`, `plan`, `validate`, and `apply` on `push/pull` requests.

**What I did:**

- Configured workflow to run on push to main and feature branches.
- Used Hashicorp's official Terraform setup action.
- Passed AWS credentials from GitHub Secrets.
- Added conditional to auto-apply only on main branch pushes.

### .github/workflows/ftp-sftp-upload.yml

```yaml
name: ftp-sftp-upload CI/CD

on:
  push:
    branches:
      - main
      - 'feature/**'

jobs:
  terraform:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v3

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v2
        with:
          terraform_version: 1.5.6

      - name: Terraform Init
        run: terraform init

      - name: Terraform Format Check
        run: terraform fmt -check

      - name: Terraform Validate
        run: terraform validate

      - name: Terraform Plan
        run: terraform plan

      - name: Terraform Apply
        if: github.ref == 'refs/heads/main'
        run: terraform apply -auto-approve
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          TF_VAR_GITHUB_TOKEN: ${{ secrets.TF_VAR_GITHUB_TOKEN }}
```
---

### Step 9: Usage and Deployment

**Purpose:**

- Run `terraform init` and `terraform apply` locally or push to GitHub to trigger workflow.
- Retrieve EC2 public IP and Transfer Family endpoint from outputs.
- Connect to EC2 via SSH with key for FTP testing.
- Use SFTP client to connect to AWS Transfer Family endpoint.

---

### terraform init

### Error

![](./img/2.init-error.png)

**What this means:**

Terraform backend configuration must be declared only once, and it must be in the root module (not inside child modules). You cannot have multiple backend configurations in your root or inside modules.

**How to fix:**
- Check your root directory for backend configuration

- You should have only one terraform { backend "s3" { ... } } block — typically this is in a file like backend.tf or directly inside your main.tf.

- Remove any duplicate backend blocks

    ![](./img/3.s3-backend-remove.png)

- If you have a backend block in main.tf and also one in backend.tf, move it to only one file.

    ![](./img/4.s3-backend-maintained-in-backend.png)

- Do NOT put a backend block inside any module (like inside `modules/aws_transfer_sftp/main.tf` or similar).

### Run:

### `terraform init -reconfigure`

![](./img/5.terraform-init-reconfigure.png)

---

### terraform plan

![](./img/6.error.png)

### Challenge Faced

While integrating the **IAM user policy module** from an external GitHub branch (`feature/understand-python-role-data-processing`), the following issues occurred:

- Terraform errors about missing required arguments (`policy_name`, `policy_statements`, `iam_user_name`).

- Unexpected/unsupported arguments like `github_user`, `s3_clean_bucket`, `s3_raw_bucket` which were not defined in the external module.

- Dependency on an unmerged branch created complexity and instability.

- Difficulty maintaining and debugging the external module integration in this project context.

### Resolution

To resolve these challenges, I **replaced the external IAM user policy module** with a **local module** defined inside my project under `/modules/iam_user_policy_sftp_csv_upload`. This local module contains only the needed variables and resources:

- `policy_name`

- `description`

- `policy_statements`

- `iam_user_name`

This makes the project:

- Fully **self-contained** and easy to maintain.

- Simplifies Terraform configurations by removing unsupported parameters.

- Avoids dependency on unmerged external branches.

---

---

### Step 10: modules/iam_user_policy_sftp_csv_upload/main.tf
*Purpose:* Create IAM Policy for Transfer Family Tagging and Attach to User
*What I did:* Created policy allowing actions like transfer:TagResource, and attached it to the IAM user

```
resource "aws_iam_policy" "custom_user_policy" {
  name        = var.policy_name
  description = var.description

  policy = jsonencode({
    Version   = "2012-10-17",
    Statement = var.policy_statements
  })
}

resource "aws_iam_user_policy_attachment" "attach_policy" {
  user       = var.iam_user_name
  policy_arn = aws_iam_policy.custom_user_policy.arn
}
```

---

### Step 11: Root main.tf (IAM Tagging Policy)
*Purpose:* Attach a separate IAM policy to allow transfer:* operations
*What I did:* Added a new root-level module instantiation to bind the new tagging policy to the IAM user

```
module "iam_user_policy_transfer_tag" {
  source         = "./modules/iam_user_policy_sftp_csv_upload"
  policy_name    = "TransferTagPolicy"
  iam_user_name  = var.iam_user_name
  description    = "Allow tagging for AWS Transfer Family server"

  policy_statements = [
    {
      Sid      = "AllowTransferTagging"
      Effect   = "Allow"
      Action   = [
        "transfer:TagResource",
        "transfer:CreateServer",
        "transfer:DescribeServer",
        "transfer:DeleteServer"
      ]
      Resource = "*"
    }
  ]
}
```

## (Updated)

### File Structure

```css
ftp-sftp-upload-project/
├── main.tf
├── variables.tf
├── outputs.tf
├── terraform.tfvars
├── README.md
├── .github/
│   └── workflows/
│       └── terraform.yml
├── scripts/
│   └── install-vsftpd.sh
└── modules/
    ├── network/
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── ec2_sftp/
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── aws_transfer_sftp/
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    └── iam_user_policy_sftp_csv_upload/
        ├── main.tf
        ├── variables.tf
        └── outputs.tf
```

### Step 1: `modules/iam_user_policy_sftp_csv_upload/main.tf`

**Purpose:** Define IAM policy resource and attach it to existing IAM user for required permissions.

**What I did:** Created local module to avoid dependency on external modules and ensure uniqueness.

```hcl
resource "aws_iam_policy" "custom_user_policy" {
  name        = var.policy_name
  description = var.description

  policy = jsonencode({
    Version   = "2012-10-17",
    Statement = var.policy_statements
  })
}

resource "aws_iam_user_policy_attachment" "attach_policy" {
  user       = var.iam_user_name
  policy_arn = aws_iam_policy.custom_user_policy.arn
}
```

### Step 2: `modules/iam_user_policy_sftp_csv_upload/variables.tf`

```hcl
variable "policy_name" {
  type        = string
  description = "Name of the IAM policy"
}

variable "description" {
  type        = string
  default     = "Custom IAM user policy"
}

variable "policy_statements" {
  type        = any
  description = "IAM policy statements in JSON format"
}

variable "iam_user_name" {
  type        = string
  description = "IAM user to attach this policy"
}
```

### Step 3: `modules/iam_user_policy_sftp_csv_upload/outputs.tf`

```hcl
output "policy_arn" {
  value       = aws_iam_policy.custom_user_policy.arn
  description = "ARN of the custom IAM policy"
}
```

### Step 4: Root `main.tf`

**Purpose:** Use the local iam_user_policy_sftp_csv_upload module, passing the required S3 bucket names and IAM user.
**What I did:** Updated module reference and variables for policy attachment.

```hcl
# Call IAM module and push credentials to GitHub Secrets.
module "github_iam_user" {
  source        = "./modules/aws_iam_user"
  iam_user_name = var.iam_user_name
  }

# Store AWS Access Key ID in GitHub repository secrets
resource "github_actions_secret" "aws_access_key_id" {
  repository      = var.github_repo
  secret_name     = "AWS_ACCESS_KEY_ID"
  plaintext_value = module.github_iam_user.access_key_id
}

# Store AWS Secret Access Key in GitHub repository secrets
resource "github_actions_secret" "aws_secret_access_key" {
  repository      = var.github_repo
  secret_name     = "AWS_SECRET_ACCESS_KEY"
  plaintext_value = module.github_iam_user.secret_access_key
}

####################################################################
# Project: Provision EC2 or AWS Transfer for SFTP CSV Upload (Spike)
####################################################################


module "network" {
  source = "./modules/network"
}

module "ec2_sftp" {
  source        = "./modules/ec2_sftp"
  instance_type = var.instance_type
  key_name      = var.key_name
  vpc_id        = module.network.vpc_id
  subnet_id     = module.network.subnet_id
  allowed_ips   = var.allowed_ips
}

module "aws_transfer_sftp" {
  source       = "./modules/aws_transfer_sftp"
  iam_role_name = var.iam_role_name
  s3_bucket    = var.s3_transfer_bucket
}

module "iam_user_policy_sftp_csv_upload" {
  source         = "./modules/iam_user_policy_sftp_csv_upload"
  policy_name    = "S3AccessPolicyForCSVUpload"
  iam_user_name  = var.iam_user_name
  description    = "Policy to allow S3 access for CSV upload"

  policy_statements = [
    {
      Sid    = "AllowS3FullAccess"
      Effect = "Allow"
      Action = "s3:*"
      Resource = [
        "arn:aws:s3:::${var.clean_data_bucket}",
        "arn:aws:s3:::${var.clean_data_bucket}/*",
        "arn:aws:s3:::${var.raw_data_bucket}",
        "arn:aws:s3:::${var.raw_data_bucket}/*"
      ]
    }
  ]
}
```

### Step 6: Root `variables.tf`

```hcl
# IAM user and GitHub integration
variable "iam_user_name" {
  description = "Name of the IAM user to create and manage"
  type        = string
}

variable "policy_arn" {
  description = "ARN of the IAM policy to attach to the IAM user"
  type        = string
}

variable "github_repo" {
  description = "GitHub repository name where secrets will be stored"
  type        = string
}

# S3 buckets for clean and raw data
variable "clean_data_name" {
  description = "S3 bucket name for clean data"
  type        = string
}

variable "clean_data_tag" {
  description = "Tag for clean data S3 bucket"
  type        = map(string)
}

variable "raw_data_name" {
  description = "S3 bucket name for raw data"
  type        = string
}

variable "raw_data_tag" {
  description = "Tag for raw data S3 bucket"
  type        = map(string)
}

variable "kms_key_description" {
  description = "KMS key description for S3 encryption"
  type        = string
}

variable "sse_algorithm" {
  description = "Server-side encryption algorithm to use (e.g., aws:kms)"
  type        = string
}

variable "pod_name" {
  description = "Project or pod name for tagging and naming resources"
  type        = string
}

variable "env" {
  description = "Environment (e.g., dev, staging, prod)"
  type        = string
}

# EC2 and networking
variable "instance_type" {
  description = "EC2 instance type for the SFTP server"
  type        = string
}

variable "key_name" {
  description = "SSH key pair name to attach to EC2 instance"
  type        = string
}

variable "allowed_ips" {
  description = "List of allowed CIDR IPs for accessing EC2 instance"
  type        = list(string)
}

# AWS Transfer Family (SFTP)
variable "iam_role_name" {
  description = "IAM role name used by AWS Transfer Family for SFTP access"
  type        = string
}

variable "s3_transfer_bucket" {
  description = "S3 bucket used by AWS Transfer Family to store files"
  type        = string
}

# Bucket names to reference in policy
variable "clean_data_bucket" {
  description = "S3 bucket name for clean data used in IAM policy"
  type        = string
}

variable "raw_data_bucket" {
  description = "S3 bucket name for raw data used in IAM policy"
  type        = string
}
```

### terraform plan

![](./img/7.terraform-plan.png)

### terraform apply -auto-approve



Summary:
- Established two viable methods for CSV upload using FTP and SFTP.
- Automated infrastructure provisioning with Terraform modules.
- Integrated IAM policies for secure access.
- Enabled CI/CD via GitHub Actions for automation.
- Created documentation and scripts to ensure repeatability and maintainability.

---

This document should guide you clearly through the entire project from environment setup to deployment and usage.

---

I'll prepare the text file and give you the download link next.
