# IAM policies for Kibertas cluster autoscaler tests
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
  default     = "kibertas-ci-role"
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
resource "aws_iam_policy" "kibertas_test_terraform" {
  name        = "KibertasTestTerraformPolicy"
  description = "Least-privileged policy for Kibertas cluster autoscaler tests"
  
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
          "eks:ListTagsForResource"
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
          "iam:PassRole"
        ]
        Resource = [
          "arn:aws:iam::*:role/kibertas-ca-*",
          "arn:aws:iam::*:role/*-cluster",
          "arn:aws:iam::*:role/*-node",
          // Otherwise you end up with:
          //   creating EKS Node Group (kibertas-ca-cluster:kibertas-ca-spot): operation error EKS: CreateNodegroup, https response error StatusCode: 400, RequestID: REQUEST_ID, InvalidRequestException: Failed to validate if SLR: AWSServiceRoleForAmazonEKSNodegroup already exists due to missing permissions for 'iam:GetRole'
          "arn:aws:iam::*:role/aws-service-role/*"
        ]
      },
      {
        Sid    = "IAMInstanceProfileManagement"
        Effect = "Allow"
        Action = [
          "iam:CreateInstanceProfile",
          "iam:DeleteInstanceProfile",
          "iam:GetInstanceProfile",
          "iam:AddRoleToInstanceProfile",
          "iam:RemoveRoleFromInstanceProfile",
          "iam:TagInstanceProfile",
          "iam:UntagInstanceProfile",
          "iam:ListInstanceProfileTags"
        ]
        Resource = [
          "arn:aws:iam::*:instance-profile/kibertas-ca-*",
          "arn:aws:iam::*:instance-profile/*-node"
        ]
      },
      {
        Sid    = "EC2NetworkingManagement"
        Effect = "Allow"
        Action = [
          "ec2:CreateSubnet",
          "ec2:DeleteSubnet",
          "ec2:DescribeSubnets",
          "ec2:ModifySubnetAttribute",
          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "ec2:DescribeSecurityGroups",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress",
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
          "ec2:GetInstanceTypesFromInstanceRequirements"
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
          // Otherwise terraform apply using the role created by this terraform will fail with:
          //   Error: reading EC2 VPC (VPC_ID_HERE) Attribute (enableDnsHostnames): UnauthorizedOperation: You are not authorized to perform this operation
          "ec2:DescribeVpcAttribute",
          "ec2:DescribeRouteTables",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeNatGateways"
        ]
        Resource = "*"
      },
      {
        Sid    = "AutoScalingManagement"
        Effect = "Allow"
        Action = [
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:DescribeAutoScalingInstances",
          "autoscaling:DescribeLaunchConfigurations",
          "autoscaling:DescribeScalingActivities",
          "autoscaling:DescribeTags",
          "autoscaling:SetDesiredCapacity",
          "autoscaling:TerminateInstanceInAutoScalingGroup"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "aws:RequestedRegion" = ["ap-northeast-1", "us-east-1", "us-west-2"]
          }
        }
      },
      {
        Sid    = "SQSManagement"
        Effect = "Allow"
        Action = [
          "sqs:CreateQueue",
          "sqs:DeleteQueue",
          "sqs:GetQueueAttributes",
          "sqs:SetQueueAttributes",
          "sqs:GetQueueUrl",
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:TagQueue",
          "sqs:UntagQueue",
          "sqs:ListQueueTags"
        ]
        Resource = "arn:aws:sqs:*:*:kibertas-ca-*"
      },
      {
        Sid    = "PricingAccess"
        Effect = "Allow"
        Action = [
          "pricing:GetProducts"
        ]
        Resource = "*"
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
    Purpose = "CI/CD for Kibertas cluster autoscaler tests"
    Project = "Kibertas"
  }
}

# Kubernetes operations policy
resource "aws_iam_policy" "kibertas_test_kubernetes" {
  name        = "KibertasTestKubernetesPolicy"
  description = "Policy for Kubernetes operations in Kibertas tests"
  
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
    Purpose = "CI/CD for Kibertas cluster autoscaler tests"
    Project = "Kibertas"
  }
}

# Helm ECR access policy
resource "aws_iam_policy" "kibertas_test_helm_ecr" {
  name        = "KibertasTestHelmECRPolicy"
  description = "Policy for Helm ECR access in Kibertas tests"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ECRPublicAccess"
        Effect = "Allow"
        Action = [
          "ecr-public:GetAuthorizationToken",
          "ecr-public:BatchCheckLayerAvailability",
          "ecr-public:GetDownloadUrlForLayer",
          "ecr-public:BatchGetImage"
        ]
        Resource = "*"
      },
      {
        Sid    = "ECRPrivateReadAccess"
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Purpose = "CI/CD for Kibertas cluster autoscaler tests"
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
resource "aws_iam_role" "kibertas_ci" {
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
    Purpose = "CI/CD for Kibertas cluster autoscaler tests"
    Project = "Kibertas"
  }
}

# Attach policies to role
resource "aws_iam_role_policy_attachment" "kibertas_ci_terraform" {
  role       = aws_iam_role.kibertas_ci.name
  policy_arn = aws_iam_policy.kibertas_test_terraform.arn
}

resource "aws_iam_role_policy_attachment" "kibertas_ci_kubernetes" {
  role       = aws_iam_role.kibertas_ci.name
  policy_arn = aws_iam_policy.kibertas_test_kubernetes.arn
}

resource "aws_iam_role_policy_attachment" "kibertas_ci_helm_ecr" {
  role       = aws_iam_role.kibertas_ci.name
  policy_arn = aws_iam_policy.kibertas_test_helm_ecr.arn
}

# Outputs
output "ci_role_name" {
  description = "Name of the created CI role"
  value       = aws_iam_role.kibertas_ci.name
}

output "ci_role_arn" {
  description = "ARN of the created CI role"
  value       = aws_iam_role.kibertas_ci.arn
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
  value       = aws_iam_policy.kibertas_test_terraform.arn
}

output "kubernetes_policy_arn" {
  description = "ARN of the Kubernetes policy"
  value       = aws_iam_policy.kibertas_test_kubernetes.arn
}

output "helm_ecr_policy_arn" {
  description = "ARN of the Helm ECR policy"
  value       = aws_iam_policy.kibertas_test_helm_ecr.arn
} 