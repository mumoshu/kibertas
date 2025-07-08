#!/bin/bash

# Fluentd E2E Test Runner with CI Role Assumption
# This script automatically assumes the CI role and runs the Fluentd e2e tests

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CI_INFRA_DIR="${SCRIPT_DIR}/testdata/terraform/ci-infra"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions (all output to stderr to avoid mixing with function returns)
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" >&2
}

# Function to check if required tools are available
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    local missing_tools=()
    
    if ! command -v aws &> /dev/null; then
        missing_tools+=("aws")
    fi
    
    if ! command -v jq &> /dev/null; then
        missing_tools+=("jq")
    fi
    
    if ! command -v terraform &> /dev/null; then
        missing_tools+=("terraform")
    fi
    
    if ! command -v go &> /dev/null; then
        missing_tools+=("go")
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_error "Please install the missing tools and try again"
        exit 1
    fi
    
    log_success "All prerequisites are available"
}

# Function to verify CI infrastructure exists
check_ci_infrastructure() {
    log_info "Checking CI infrastructure..."
    
    if [ ! -d "${CI_INFRA_DIR}" ]; then
        log_error "CI infrastructure directory not found: ${CI_INFRA_DIR}"
        log_error "Please ensure the ci-infra terraform project exists"
        exit 1
    fi
    
    if [ ! -f "${CI_INFRA_DIR}/ci-iam-setup.tf" ]; then
        log_error "CI infrastructure terraform file not found: ${CI_INFRA_DIR}/ci-iam-setup.tf"
        exit 1
    fi
    
    log_success "CI infrastructure found"
}

# Function to get the CI role ARN
get_ci_role_arn() {
    log_info "Getting CI role ARN..."
    
    pushd "${CI_INFRA_DIR}" > /dev/null
    
    if ! terraform show -json > /dev/null 2>&1; then
        log_error "Terraform state not found or invalid in ${CI_INFRA_DIR}"
        log_error "Please run 'terraform init' and 'terraform apply' in the ci-infra directory first"
        popd > /dev/null
        exit 1
    fi
    
    local role_arn
    if ! role_arn=$(terraform output -raw ci_role_arn 2>/dev/null); then
        log_error "Failed to get CI role ARN from terraform output"
        log_error "Please ensure the CI infrastructure is deployed"
        popd > /dev/null
        exit 1
    fi
    
    popd > /dev/null
    
    if [ -z "${role_arn}" ]; then
        log_error "CI role ARN is empty"
        exit 1
    fi
    
    echo "${role_arn}"
}

# Function to assume the CI role
assume_ci_role() {
    local role_arn="$1"
    local session_name="kibertas-fluent-test-$(date +%s)"
    
    log_info "Assuming CI role: ${role_arn}"
    log_info "Session name: ${session_name}"
    
    local creds_json
    if ! creds_json=$(aws sts assume-role \
        --role-arn "${role_arn}" \
        --role-session-name "${session_name}" \
        --output json 2>/dev/null); then
        log_error "Failed to assume CI role"
        log_error "Please check your AWS credentials and role trust policy"
        exit 1
    fi
    
    # Export credentials to environment
    export AWS_ACCESS_KEY_ID=$(echo "${creds_json}" | jq -r '.Credentials.AccessKeyId')
    export AWS_SECRET_ACCESS_KEY=$(echo "${creds_json}" | jq -r '.Credentials.SecretAccessKey')
    export AWS_SESSION_TOKEN=$(echo "${creds_json}" | jq -r '.Credentials.SessionToken')
    
    # Verify the role assumption worked
    local identity
    if ! identity=$(aws sts get-caller-identity --output json 2>/dev/null); then
        log_error "Failed to verify assumed role identity"
        exit 1
    fi
    
    local assumed_arn=$(echo "${identity}" | jq -r '.Arn')
    log_success "Successfully assumed role: ${assumed_arn}"
}

# Function to check required environment variables
check_test_environment() {
    log_info "Checking test environment variables..."
    
    local missing_vars=()
    
    if [ -z "${KIBERTAS_PREFIX:-}" ]; then
        missing_vars+=("KIBERTAS_PREFIX")
    fi
    
    if [ -z "${VPC_ID:-}" ]; then
        missing_vars+=("VPC_ID")
    fi
    
    if [ -z "${TERRAFORM_STATE_BUCKET:-}" ]; then
        missing_vars+=("TERRAFORM_STATE_BUCKET")
    fi
    
    if [ -z "${TERRAFORM_STATE_KEY:-}" ]; then
        missing_vars+=("TERRAFORM_STATE_KEY")
    fi
    
    if [ -z "${EKS_ACCESS_PRINCIPAL_ARN:-}" ]; then
        missing_vars+=("EKS_ACCESS_PRINCIPAL_ARN")
    fi
    
    if [ ${#missing_vars[@]} -ne 0 ]; then
        log_error "Missing required environment variables: ${missing_vars[*]}"
        log_error ""
        log_error "Please set the following environment variables:"
        log_error "  export KIBERTAS_PREFIX=\"your-test-prefix\""
        log_error "  export VPC_ID=\"vpc-xxxxxxxxx\""
        log_error "  export TERRAFORM_STATE_BUCKET=\"your-terraform-state-bucket\""
        log_error "  export TERRAFORM_STATE_KEY=\"fluent-test-state-key\""
        log_error "  export EKS_ACCESS_PRINCIPAL_ARN=\"arn:aws:iam::account:role/your-role\""
        exit 1
    fi
    
    log_success "All required environment variables are set"
}

# Function to run the Fluentd e2e tests
run_fluent_tests() {
    log_info "Running Fluentd e2e tests..."
    
    cd "${PROJECT_ROOT}"
    
    log_info "Test configuration:"
    log_info "  KIBERTAS_PREFIX: ${KIBERTAS_PREFIX}"
    log_info "  VPC_ID: ${VPC_ID}"
    log_info "  TERRAFORM_STATE_BUCKET: ${TERRAFORM_STATE_BUCKET}"
    log_info "  TERRAFORM_STATE_KEY: ${TERRAFORM_STATE_KEY}"
    log_info "  EKS_ACCESS_PRINCIPAL_ARN: ${EKS_ACCESS_PRINCIPAL_ARN}"
    
    if go test -v -tags ekstest -timeout 25m ./cmd/fluent/; then
        log_success "Fluentd e2e tests completed successfully!"
    else
        log_error "Fluentd e2e tests failed!"
        exit 1
    fi
}

# Function to display usage information
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Fluentd E2E Test Runner with CI Role Assumption

This script automatically assumes the CI role and runs the Fluentd e2e tests.

Required Environment Variables:
  KIBERTAS_PREFIX          - Test prefix for resource naming
  VPC_ID                   - VPC ID for test infrastructure
  TERRAFORM_STATE_BUCKET   - S3 bucket for terraform state
  TERRAFORM_STATE_KEY      - S3 key for terraform state
  EKS_ACCESS_PRINCIPAL_ARN - Principal ARN for EKS access

Options:
  -h, --help    Show this help message

Example:
  export KIBERTAS_PREFIX="fluent-test-\$(date +%Y%m%d-%H%M%S)"
  export VPC_ID="vpc-xxxxxxxxx"
  export TERRAFORM_STATE_BUCKET="my-terraform-state-bucket"
  export TERRAFORM_STATE_KEY="fluent-test/terraform.tfstate"
  export EKS_ACCESS_PRINCIPAL_ARN="arn:aws:iam::123456789012:role/my-ci-role"
  
  $0

Prerequisites:
  - aws CLI configured with permissions to assume the CI role
  - jq for JSON processing
  - terraform with CI infrastructure deployed
  - go for running tests

EOF
}

# Main function
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    log_info "Starting Fluentd E2E test runner..."
    
    # Run all checks and preparations
    check_prerequisites
    check_ci_infrastructure
    check_test_environment
    
    # Get CI role ARN and assume the role
    local ci_role_arn
    ci_role_arn=$(get_ci_role_arn)
    assume_ci_role "${ci_role_arn}"
    
    # Update EKS_ACCESS_PRINCIPAL_ARN to use the assumed CI role
    export EKS_ACCESS_PRINCIPAL_ARN="${ci_role_arn}"
    log_info "Using CI role as EKS access principal: ${EKS_ACCESS_PRINCIPAL_ARN}"
    
    # Run the tests
    run_fluent_tests
    
    log_success "All operations completed successfully!"
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi