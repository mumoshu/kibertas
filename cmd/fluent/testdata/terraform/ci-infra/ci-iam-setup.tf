# IAM policies for Kibertas Fluentd tests
# This Terraform configuration creates least-privileged IAM policies and a role for CI/CD

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  type        = string
  description = "AWS region for the CI setup"
  default     = "ap-northeast-1"
}

variable "ci_role_name" {
  type        = string
  description = "Name for the CI role"
  default     = "kibertas-fluent-ci-role"
}

variable "github_org" {
  type        = string
  description = "GitHub organization name for OIDC trust"
  default     = ""
}

variable "github_repo" {
  type        = string
  description = "GitHub repository name for OIDC trust (optional, if empty allows all repos in org)"
  default     = ""
}

variable "trusted_iam_arns" {
  type        = list(string)
  description = "List of IAM user/role ARNs that can assume this role"
  default     = []
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

# Core Terraform policy for infrastructure management
resource "aws_iam_policy" "kibertas_fluent_test_terraform" {
  name        = "KibertasFluentTestTerraformPolicy"
  description = "Least-privileged policy for Kibertas Fluentd tests"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EKSClusterManagement"
        Effect = "Allow"
        Action = [
          "eks:CreateCluster",
          "eks:DeleteCluster",
          "eks:DescribeCluster",
          "eks:UpdateClusterConfig",
          "eks:UpdateClusterVersion",
          "eks:TagResource",
          "eks:UntagResource",
          "eks:ListTagsForResource",
          "eks:CreateAccessEntry",
          "eks:DeleteAccessEntry",
          "eks:DescribeAccessEntry",
          "eks:AssociateAccessPolicy",
          "eks:DisassociateAccessPolicy",
          "eks:ListAccessEntries",
          "eks:ListAssociatedAccessPolicies"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "aws:RequestedRegion" = ["ap-northeast-1", "us-east-1", "us-west-2"]
          }
        }
      },
      {
        Sid    = "EKSNodeGroupManagement"
        Effect = "Allow"
        Action = [
          "eks:CreateNodegroup",
          "eks:DeleteNodegroup",
          "eks:DescribeNodegroup",
          "eks:UpdateNodegroupConfig",
          "eks:UpdateNodegroupVersion",
          "eks:ListNodegroups"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "aws:RequestedRegion" = ["ap-northeast-1", "us-east-1", "us-west-2"]
          }
        }
      },
      {
        Sid    = "IAMRoleManagement"
        Effect = "Allow"
        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:GetRole",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:GetRolePolicy",
          "iam:TagRole",
          "iam:UntagRole",
          "iam:ListRoleTags",
          "iam:PassRole",
          "iam:CreateInstanceProfile",
          "iam:DeleteInstanceProfile",
          "iam:GetInstanceProfile",
          "iam:AddRoleToInstanceProfile",
          "iam:RemoveRoleFromInstanceProfile",
          "iam:TagInstanceProfile",
          "iam:UntagInstanceProfile",
          "iam:ListInstanceProfileTags",
          "iam:ListInstanceProfilesForRole"
        ]
        Resource = [
          "arn:aws:iam::*:role/*-fluent-*",
          "arn:aws:iam::*:role/*-cluster",
          "arn:aws:iam::*:role/*-node",
          "arn:aws:iam::*:instance-profile/*-fluent-*",
          "arn:aws:iam::*:instance-profile/*-node",
          "arn:aws:iam::*:role/aws-service-role/*"
        ]
      },
      {
        Sid    = "EC2SubnetManagement"
        Effect = "Allow"
        Action = [
          "ec2:CreateSubnet",
          "ec2:DeleteSubnet",
          "ec2:DescribeSubnets",
          "ec2:ModifySubnetAttribute"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "aws:RequestedRegion" = ["ap-northeast-1", "us-east-1", "us-west-2"]
          }
        }
      },
      {
        Sid    = "EC2SecurityGroupManagement"
        Effect = "Allow"
        Action = [
          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSecurityGroupRules",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "aws:RequestedRegion" = ["ap-northeast-1", "us-east-1", "us-west-2"]
          }
        }
      },
      {
        Sid    = "EC2TagManagement"
        Effect = "Allow"
        Action = [
          "ec2:CreateTags",
          "ec2:DeleteTags",
          "ec2:DescribeTags"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "aws:RequestedRegion" = ["ap-northeast-1", "us-east-1", "us-west-2"]
          }
        }
      },
      {
        Sid    = "EC2InstanceManagement"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceTypes",
          "ec2:DescribeInstanceTypeOfferings",
          "ec2:DescribeImages",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeSpotPriceHistory",
          "ec2:RunInstances",
          "ec2:TerminateInstances",
          "ec2:CreateLaunchTemplate",
          "ec2:DeleteLaunchTemplate",
          "ec2:DescribeLaunchTemplates",
          "ec2:DescribeLaunchTemplateVersions",
          "ec2:CreateFleet",
          "ec2:GetInstanceTypesFromInstanceRequirements",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DeleteNetworkInterface",
          "ec2:DetachNetworkInterface"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "aws:RequestedRegion" = ["ap-northeast-1", "us-east-1", "us-west-2"]
          }
        }
      },
      {
        Sid    = "VPCReadAccess"
        Effect = "Allow"
        Action = [
          "ec2:DescribeVpcs",
          "ec2:DescribeVpcAttribute",
          "ec2:DescribeRouteTables",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeNatGateways"
        ]
        Resource = "*"
      },
      {
        Sid    = "S3ListAllBuckets"
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets"
        ]
        Resource = "*"
      },
      {
        Sid    = "S3BucketLifecycleManagement"
        Effect = "Allow"
        Action = [
          "s3:CreateBucket",
          "s3:DeleteBucket",
          "s3:GetBucketLocation",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:ListBucketVersions"
        ]
        Resource = [
          "arn:aws:s3:::*-fluent-*",
          "arn:aws:s3:::*-bucket"
        ]
      },
      {
        Sid    = "S3BucketConfigurationRead"
        Effect = "Allow"
        Action = [
          "s3:GetBucketAcl",
          "s3:GetBucketCors",
          "s3:GetBucketLifecycleConfiguration",
          "s3:GetLifecycleConfiguration",
          "s3:GetBucketNotification",
          "s3:GetBucketPolicy",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketVersioning",
          "s3:GetBucketTagging",
          "s3:GetBucketWebsite",
          "s3:GetBucketLogging",
          "s3:GetBucketRequestPayment",
          "s3:GetEncryptionConfiguration",
          "s3:GetBucketObjectLockConfiguration",
          "s3:GetBucketReplication",
          "s3:GetReplicationConfiguration",
          "s3:GetAccelerateConfiguration"
        ]
        Resource = [
          "arn:aws:s3:::*-fluent-*",
          "arn:aws:s3:::*-bucket"
        ]
      },
      {
        Sid    = "S3BucketConfigurationWrite"
        Effect = "Allow"
        Action = [
          "s3:PutBucketPublicAccessBlock",
          "s3:PutBucketVersioning",
          "s3:PutBucketTagging"
        ]
        Resource = [
          "arn:aws:s3:::*-fluent-*",
          "arn:aws:s3:::*-bucket"
        ]
      },
      {
        Sid    = "S3ObjectAccessForFluentd"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:DeleteObjectVersion",
          "s3:AbortMultipartUpload",
          "s3:ListMultipartUploadParts"
        ]
        Resource = [
          "arn:aws:s3:::*-fluent-*/*",
          "arn:aws:s3:::*-bucket/*"
        ]
      },
      {
        Sid    = "S3TerraformStateAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket",
          "s3:GetBucketLocation",
          "s3:GetBucketVersioning"
        ]
        Resource = [
          "arn:aws:s3:::*-tfstates",
          "arn:aws:s3:::*-tfstates/*",
          "arn:aws:s3:::*-terraform-state",
          "arn:aws:s3:::*-terraform-state/*"
        ]
      },
      {
        Sid    = "CallerIdentity"
        Effect = "Allow"
        Action = [
          "sts:GetCallerIdentity"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Purpose = "CI/CD for Kibertas Fluentd tests"
    Project = "Kibertas"
  }
}

# Kubernetes operations policy
resource "aws_iam_policy" "kibertas_fluent_test_kubernetes" {
  name        = "KibertasFluentTestKubernetesPolicy"
  description = "Policy for Kubernetes operations in Kibertas Fluentd tests"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EKSClusterAccess"
        Effect = "Allow"
        Action = [
          "eks:DescribeCluster",
          "eks:ListClusters"
        ]
        Resource = "*"
      },
      {
        Sid    = "EKSNodeGroupAccess"
        Effect = "Allow"
        Action = [
          "eks:DescribeNodegroup",
          "eks:ListNodegroups"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Purpose = "CI/CD for Kibertas Fluentd tests"
    Project = "Kibertas"
  }
}

# S3 access policy for test execution (reading logs from S3)
resource "aws_iam_policy" "kibertas_fluent_test_s3_access" {
  name        = "KibertasFluentTestS3AccessPolicy"
  description = "Policy for S3 access during Fluentd tests"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3ListAllBucketsForTests"
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets"
        ]
        Resource = "*"
      },
      {
        Sid    = "S3ReadAccessForTests"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "s3:GetBucketLocation",
          "s3:ListBucketMultipartUploads",
          "s3:ListBucketVersions"
        ]
        Resource = [
          "arn:aws:s3:::*-fluent-*",
          "arn:aws:s3:::*-fluent-*/*",
          "arn:aws:s3:::*-bucket",
          "arn:aws:s3:::*-bucket/*"
        ]
      }
    ]
  })

  tags = {
    Purpose = "CI/CD for Kibertas Fluentd tests"
    Project = "Kibertas"
  }
}

# Data source for GitHub OIDC provider (if it exists)
data "aws_iam_openid_connect_provider" "github" {
  count = var.github_org != "" ? 1 : 0
  url   = "https://token.actions.githubusercontent.com"
}

# Create GitHub OIDC provider if it doesn't exist and github_org is provided
resource "aws_iam_openid_connect_provider" "github" {
  count = var.github_org != "" && length(data.aws_iam_openid_connect_provider.github) == 0 ? 1 : 0
  
  url = "https://token.actions.githubusercontent.com"
  
  client_id_list = [
    "sts.amazonaws.com"
  ]
  
  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58a3a8518e8759bf075b76b750d4f2df264fcd"
  ]

  tags = {
    Purpose = "GitHub Actions OIDC for Kibertas CI"
    Project = "Kibertas"
  }
}

# IAM role for CI
resource "aws_iam_role" "kibertas_fluent_ci" {
  name = var.ci_role_name
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = length(var.trusted_iam_arns) > 0 || var.github_org != "" ? concat(
      # Allow specified IAM users/roles to assume this role
      length(var.trusted_iam_arns) > 0 ? [{
        Effect = "Allow"
        Principal = {
          AWS = var.trusted_iam_arns
        }
        Action = "sts:AssumeRole"
      }] : [],
      # Allow GitHub Actions OIDC to assume this role
      var.github_org != "" ? [{
        Effect = "Allow"
        Principal = {
          Federated = try(
            data.aws_iam_openid_connect_provider.github[0].arn,
            aws_iam_openid_connect_provider.github[0].arn
          )
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          StringLike = var.github_repo != "" ? {
            "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:*"
          } : {
            "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/*:*"
          }
        }
      }] : []
    ) : [
      # Default: Allow current IAM user/role running terraform to assume this role
      # This ensures the policy is never empty and provides a practical fallback
      {
        Effect = "Allow"
        Principal = {
          AWS = data.aws_caller_identity.current.arn
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
  
  tags = {
    Purpose = "CI/CD for Kibertas Fluentd tests"
    Project = "Kibertas"
  }
}

# Attach policies to role
resource "aws_iam_role_policy_attachment" "kibertas_fluent_ci_terraform" {
  role       = aws_iam_role.kibertas_fluent_ci.name
  policy_arn = aws_iam_policy.kibertas_fluent_test_terraform.arn
}

resource "aws_iam_role_policy_attachment" "kibertas_fluent_ci_kubernetes" {
  role       = aws_iam_role.kibertas_fluent_ci.name
  policy_arn = aws_iam_policy.kibertas_fluent_test_kubernetes.arn
}

resource "aws_iam_role_policy_attachment" "kibertas_fluent_ci_s3_access" {
  role       = aws_iam_role.kibertas_fluent_ci.name
  policy_arn = aws_iam_policy.kibertas_fluent_test_s3_access.arn
}

# Outputs
output "ci_role_name" {
  description = "Name of the created CI role"
  value       = aws_iam_role.kibertas_fluent_ci.name
}

output "ci_role_arn" {
  description = "ARN of the created CI role"
  value       = aws_iam_role.kibertas_fluent_ci.arn
}

output "github_oidc_provider_arn" {
  description = "ARN of the GitHub OIDC provider (if created)"
  value       = var.github_org != "" ? try(
    data.aws_iam_openid_connect_provider.github[0].arn,
    aws_iam_openid_connect_provider.github[0].arn
  ) : null
}

output "terraform_policy_arn" {
  description = "ARN of the Terraform policy"
  value       = aws_iam_policy.kibertas_fluent_test_terraform.arn
}

output "kubernetes_policy_arn" {
  description = "ARN of the Kubernetes policy"
  value       = aws_iam_policy.kibertas_fluent_test_kubernetes.arn
}

output "s3_access_policy_arn" {
  description = "ARN of the S3 access policy"
  value       = aws_iam_policy.kibertas_fluent_test_s3_access.arn
}