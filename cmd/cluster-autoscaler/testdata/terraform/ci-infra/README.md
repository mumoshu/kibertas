# CI Infrastructure Setup for Kibertas Cluster Autoscaler Tests

This directory contains Terraform configuration and IAM policies for setting up least-privileged CI/CD infrastructure for the Kibertas cluster autoscaler tests.

## Files

- `ci-iam-setup.tf` - Main Terraform configuration for IAM policies and role
- `terraform-policy.json` - Core Terraform policy (for AWS CLI setup)
- `kubernetes-policy.json` - Kubernetes operations policy (for AWS CLI setup)
- `helm-ecr-policy.json` - Helm ECR access policy (for AWS CLI setup)

## Quick Setup with Terraform

Once you run `terraform init`, `terraform plan`, and `terraform apply`, you will have a role with the following policies:
- `terraform-policy.json`
- `kubernetes-policy.json`
- `helm-ecr-policy.json`

You can run `terraform output ci_role_arn` to get the role ARN.

## Configuration Options

### Default Configuration

If you don't specify any GitHub organization or trusted IAM ARNs, the role will have a default trust policy that allows the current IAM user/role running `terraform apply` to assume it. This ensures the role is always valid and immediately usable by the person deploying it.

### For GitHub Actions OIDC

To configure the role for GitHub Actions OIDC:

```bash
terraform apply \
  -var="github_org=your-github-org" \
  -var="github_repo=your-repo-name"
```

If you omit `github_repo`, the role will trust all repositories in the organization.

### For IAM User/Role Assumption

To allow specific IAM users or roles to assume this role:

```bash
terraform apply \
  -var='trusted_iam_arns=["arn:aws:iam::123456789012:user/ci-user", "arn:aws:iam::123456789012:role/another-role"]'
```

### Combined Configuration

You can configure both GitHub Actions OIDC and IAM user/role assumption:

```bash
terraform apply \
  -var="github_org=your-github-org" \
  -var="github_repo=your-repo-name" \
  -var='trusted_iam_arns=["arn:aws:iam::123456789012:user/ci-user"]' \
  -var="aws_region=us-east-1" \
  -var="ci_role_name=my-custom-ci-role"
```

## GitHub Actions Setup

1. **Configure the role with your GitHub organization:**
   ```bash
   terraform apply \
     -var="github_org=your-github-org" \
     -var="github_repo=your-repo-name"
   ```

2. **Add the role ARN to your GitHub repository secrets:**
   - `AWS_ROLE_ARN` - The role ARN from `terraform output ci_role_arn`

3. **Use in your GitHub Actions workflow:**
   ```yaml
   jobs:
     test:
       runs-on: ubuntu-latest
       permissions:
         id-token: write
         contents: read
       steps:
         - name: Configure AWS credentials
           uses: aws-actions/configure-aws-credentials@v4
           with:
             role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
             aws-region: ap-northeast-1
   ```

## Local Setup

After creating the role, you can use it in another terminal session or script to run programs that need the role's policies:

```bash
# Do not forget cd if you have not yet in this directory
$ pushd cmd/cluster-autoscaler/testdata/terraform/ci-infra/

# Verify that you are not using the role
$ aws sts get-caller-identity

# Assume the role
$ eval "$(
  ROLE_ARN=$(terraform output -raw ci_role_arn) && \
  CREDS=$(aws sts assume-role --role-arn "$ROLE_ARN" --role-session-name "kibertas-$(date +%s)" --output json) && \
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

# Test EC2 permissions  
aws ec2 describe-instances
aws ec2 describe-vpcs
```

**Note**: The role credentials are temporary and will expire (typically after 1 hour). You'll need to re-assume the role when they expire.

### Running Tests

```bash
# Do not forget popd if you have not yet in the project root directory
$ popd

# Run the cluster-autoscaler tests
$ go test -v -tags ekstest ./cmd/cluster-autoscaler -run TestClusterAutoscalerScaleUpFromNonZero
```
