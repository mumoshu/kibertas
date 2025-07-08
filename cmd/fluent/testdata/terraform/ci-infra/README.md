# Fluentd CI Infrastructure

This Terraform configuration creates the necessary IAM roles and policies for running Kibertas Fluentd e2e tests in CI/CD environments.

## Overview

The CI infrastructure creates:
- IAM role for CI/CD execution
- Terraform policy for infrastructure management
- Kubernetes policy for EKS cluster operations
- S3 access policy for reading test logs
- Optional GitHub OIDC provider for GitHub Actions

## Permissions

The created IAM role has the following capabilities:

### Terraform Infrastructure Management
- Create/manage EKS clusters and node groups
- Create/manage IAM roles and instance profiles for test infrastructure
- Create/manage EC2 subnets and security groups
- Create/manage S3 buckets for log storage
- Manage EC2 instances and launch templates

### Kubernetes Operations
- Describe EKS clusters and node groups
- Access cluster information

### S3 Operations for Testing
- Read objects from S3 buckets created by test infrastructure
- List bucket contents to verify log delivery

## Usage

### Prerequisites

1. AWS CLI configured with appropriate permissions
2. Terraform installed

### Deployment

```bash
# Initialize Terraform
terraform init

# Plan the deployment
terraform plan

# Apply the configuration
terraform apply

# To specify custom values
terraform apply \
  -var="ci_role_name=my-fluent-ci-role" \
  -var="aws_region=us-west-2" \
  -var="github_org=myorg" \
  -var="github_repo=myrepo"
```

### GitHub Actions Integration

To use with GitHub Actions, provide the GitHub organization and repository:

```bash
terraform apply \
  -var="github_org=chatwork" \
  -var="github_repo=kibertas"
```

### Manual IAM User/Role Trust

To allow specific IAM users or roles to assume the CI role:

```bash
terraform apply \
  -var='trusted_iam_arns=["arn:aws:iam::123456789012:user/ci-user"]'
```

## Outputs

- `ci_role_name`: Name of the created CI role
- `ci_role_arn`: ARN of the created CI role
- `github_oidc_provider_arn`: ARN of the GitHub OIDC provider (if created)
- `terraform_policy_arn`: ARN of the Terraform policy
- `kubernetes_policy_arn`: ARN of the Kubernetes policy
- `s3_access_policy_arn`: ARN of the S3 access policy

## Security Considerations

- The role is designed with least-privilege principles
- Resource access is restricted to specific patterns (e.g., `*-fluent-*` for S3 buckets)
- Regional restrictions are applied where applicable
- GitHub OIDC trust is scoped to specific organization/repository

## Local Setup

After creating the role, you can use it in another terminal session or script to run programs that need the role's policies:

```bash
# Do not forget cd if you have not yet in this directory
$ pushd cmd/fluent/testdata/terraform/ci-infra/

# Verify that you are not using the role
$ aws sts get-caller-identity

# Assume the role
$ eval "$(
  ROLE_ARN=$(terraform output -raw ci_role_arn) && \
  CREDS=$(aws sts assume-role --role-arn "$ROLE_ARN" --role-session-name "kibertas-fluent-$(date +%s)" --output json) && \
  echo "export AWS_ACCESS_KEY_ID='$(echo $CREDS | jq -r .Credentials.AccessKeyId)'" && \
  echo "export AWS_SECRET_ACCESS_KEY='$(echo $CREDS | jq -r .Credentials.SecretAccessKey)'" && \
  echo "export AWS_SESSION_TOKEN='$(echo $CREDS | jq -r .Credentials.SessionToken)'"
)"

# Verify that you are using the role
$ aws sts get-caller-identity
```

### Verifying Role Permissions

Test that the role has the expected permissions:

```bash
# After assuming the role, test various permissions:

# Test EKS permissions
aws eks list-clusters
aws eks describe-cluster --name your-cluster-name

# Test S3 permissions
aws s3 ls
aws s3 ls s3://your-test-bucket

# Test EC2 permissions  
aws ec2 describe-instances
aws ec2 describe-vpcs
```

**Note**: The role credentials are temporary and will expire (typically after 1 hour). You'll need to re-assume the role when they expire.

### Running Tests

```bash
# Do not forget popd if you have not yet in the project root directory
$ popd

# Run the Fluentd e2e tests
$ go test -v -tags ekstest ./cmd/fluent/
```

## Test Integration

The created role can be used in the Fluentd e2e test by:

1. Assuming the role in your CI environment
2. Setting the appropriate environment variables for the test
3. Running the test with the assumed role credentials

Example for GitHub Actions:

```yaml
- name: Configure AWS credentials
  uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: ${{ steps.terraform.outputs.ci_role_arn }}
    aws-region: ap-northeast-1

- name: Run Fluentd e2e test
  run: go test -tags ekstest ./cmd/fluent/
  env:
    PREFIX: test-${{ github.run_id }}
    VPC_ID: ${{ secrets.VPC_ID }}
    TERRAFORM_STATE_BUCKET: ${{ secrets.TERRAFORM_STATE_BUCKET }}
    TERRAFORM_STATE_KEY: fluent-test-${{ github.run_id }}
    EKS_ACCESS_PRINCIPAL_ARN: ${{ steps.terraform.outputs.ci_role_arn }}
```