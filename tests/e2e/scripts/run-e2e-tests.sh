#!/bin/bash
# E2E Test Suite for Package Repository Server

set -e

# Configuration
REPO_URL="${REPO_URL:-http://package-repo}"
API_URL="${API_URL:-http://package-repo:8080}"
API_KEY="${API_KEY:-test-api-key-12345}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

log_failure() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

assert_equals() {
    local expected="$1"
    local actual="$2"
    local message="$3"

    if [ "$expected" = "$actual" ]; then
        log_success "$message"
        return 0
    else
        log_failure "$message (expected: '$expected', got: '$actual')"
        return 1
    fi
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local message="$3"

    if echo "$haystack" | grep -q "$needle"; then
        log_success "$message"
        return 0
    else
        log_failure "$message (expected to find: '$needle')"
        return 1
    fi
}

assert_http_status() {
    local expected="$1"
    local actual="$2"
    local message="$3"

    if [ "$expected" = "$actual" ]; then
        log_success "$message"
        return 0
    else
        log_failure "$message (expected HTTP $expected, got HTTP $actual)"
        return 1
    fi
}

# Wait for service to be ready
wait_for_service() {
    log_info "Waiting for package repository service..."
    local max_attempts=30
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if curl -sf "${API_URL}/health" > /dev/null 2>&1; then
            log_info "Service is ready!"
            return 0
        fi
        log_info "Attempt $attempt/$max_attempts - waiting..."
        sleep 2
        ((attempt++))
    done

    log_failure "Service did not become ready in time"
    exit 1
}

# Test: Health endpoint
test_health_endpoint() {
    log_info "Testing health endpoint..."

    local response=$(curl -sf "${API_URL}/health")
    local status=$(echo "$response" | jq -r '.status')

    assert_equals "healthy" "$status" "Health endpoint returns healthy status"
}

# Test: Readiness endpoint
test_readiness_endpoint() {
    log_info "Testing readiness endpoint..."

    local response=$(curl -sf "${API_URL}/ready")
    local status=$(echo "$response" | jq -r '.status')

    assert_equals "ready" "$status" "Readiness endpoint returns ready status"
}

# Test: List packages (initially empty)
test_list_packages_empty() {
    log_info "Testing package listing (empty)..."

    local response=$(curl -sf "${API_URL}/api/v1/packages")
    local total=$(echo "$response" | jq -r '.total')

    assert_equals "0" "$total" "Package list is initially empty"
}

# Test: Upload without API key fails
test_upload_without_api_key() {
    log_info "Testing upload without API key..."

    local status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST \
        -F "file=@/test-packages/mypackage_1.0.0_amd64.deb" \
        "${API_URL}/api/v1/upload/deb")

    assert_http_status "401" "$status" "Upload without API key returns 401"
}

# Test: Upload with invalid API key fails
test_upload_with_invalid_api_key() {
    log_info "Testing upload with invalid API key..."

    local status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST \
        -H "X-API-Key: wrong-key" \
        -F "file=@/test-packages/mypackage_1.0.0_amd64.deb" \
        "${API_URL}/api/v1/upload/deb")

    assert_http_status "401" "$status" "Upload with invalid API key returns 401"
}

# Test: Upload DEB package
test_upload_deb_package() {
    log_info "Testing DEB package upload..."

    local response=$(curl -sf \
        -X POST \
        -H "X-API-Key: ${API_KEY}" \
        -F "file=@/test-packages/mypackage_1.0.0_amd64.deb" \
        "${API_URL}/api/v1/upload/deb")

    local success=$(echo "$response" | jq -r '.success')
    assert_equals "true" "$success" "DEB package upload succeeds"
}

# Test: List packages after upload
test_list_packages_after_upload() {
    log_info "Testing package listing after upload..."

    # Give the processor time to complete
    sleep 2

    local response=$(curl -sf "${API_URL}/api/v1/packages/deb")
    local total=$(echo "$response" | jq -r '.total')

    if [ "$total" -ge 1 ]; then
        log_success "Package list contains uploaded package (total: $total)"
    else
        log_failure "Package list should contain at least 1 package (got: $total)"
    fi
}

# Test: Invalid package type
test_invalid_package_type() {
    log_info "Testing invalid package type..."

    local status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST \
        -H "X-API-Key: ${API_KEY}" \
        -F "file=@/test-packages/mypackage_1.0.0_amd64.deb" \
        "${API_URL}/api/v1/upload/invalid")

    assert_http_status "400" "$status" "Invalid package type returns 400"
}

# Test: APT setup script
test_apt_setup_script() {
    log_info "Testing APT setup script..."

    local response=$(curl -sf "${API_URL}/setup/apt")

    assert_contains "$response" "#!/bin/bash" "APT setup script has bash shebang"
    assert_contains "$response" "apt-get" "APT setup script contains apt-get"
}

# Test: RPM setup script
test_rpm_setup_script() {
    log_info "Testing RPM setup script..."

    local response=$(curl -sf "${API_URL}/setup/rpm")

    assert_contains "$response" "#!/bin/bash" "RPM setup script has bash shebang"
}

# Test: Arch setup script
test_arch_setup_script() {
    log_info "Testing Arch setup script..."

    local response=$(curl -sf "${API_URL}/setup/arch")

    assert_contains "$response" "#!/bin/bash" "Arch setup script has bash shebang"
    assert_contains "$response" "pacman" "Arch setup script contains pacman"
}

# Test: Alpine setup script
test_alpine_setup_script() {
    log_info "Testing Alpine setup script..."

    local response=$(curl -sf "${API_URL}/setup/alpine")

    assert_contains "$response" "#!/bin/sh" "Alpine setup script has sh shebang"
}

# Test: Delete without API key fails
test_delete_without_api_key() {
    log_info "Testing delete without API key..."

    local status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X DELETE \
        "${API_URL}/api/v1/packages/deb/mypackage")

    assert_http_status "401" "$status" "Delete without API key returns 401"
}

# Test: Rebuild without API key fails
test_rebuild_without_api_key() {
    log_info "Testing rebuild without API key..."

    local status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST \
        "${API_URL}/api/v1/repos/deb/rebuild")

    assert_http_status "401" "$status" "Rebuild without API key returns 401"
}

# Test: API key via Authorization header
test_authorization_bearer_header() {
    log_info "Testing Authorization Bearer header..."

    local response=$(curl -sf "${API_URL}/api/v1/packages" \
        -H "Authorization: Bearer ${API_KEY}")

    local total=$(echo "$response" | jq -r '.total')

    # Just verify it doesn't fail
    if [ -n "$total" ]; then
        log_success "Authorization Bearer header works"
    else
        log_failure "Authorization Bearer header failed"
    fi
}

# Test: Pagination
test_pagination() {
    log_info "Testing pagination..."

    local response=$(curl -sf "${API_URL}/api/v1/packages?limit=5&offset=0")

    # Just verify the response has the expected structure
    local has_total=$(echo "$response" | jq 'has("total")')
    local has_packages=$(echo "$response" | jq 'has("packages")')

    if [ "$has_total" = "true" ] && [ "$has_packages" = "true" ]; then
        log_success "Pagination response has correct structure"
    else
        log_failure "Pagination response missing expected fields"
    fi
}

# Main test runner
main() {
    echo "========================================"
    echo "  Package Repository E2E Test Suite"
    echo "========================================"
    echo ""

    wait_for_service

    echo ""
    echo "Running tests..."
    echo "----------------------------------------"

    # Health checks
    test_health_endpoint
    test_readiness_endpoint

    # Package listing
    test_list_packages_empty

    # Authentication tests
    test_upload_without_api_key
    test_upload_with_invalid_api_key
    test_delete_without_api_key
    test_rebuild_without_api_key
    test_authorization_bearer_header

    # Package upload
    test_upload_deb_package
    test_list_packages_after_upload

    # Invalid requests
    test_invalid_package_type

    # Setup scripts
    test_apt_setup_script
    test_rpm_setup_script
    test_arch_setup_script
    test_alpine_setup_script

    # Pagination
    test_pagination

    echo ""
    echo "========================================"
    echo "  Test Results"
    echo "========================================"
    echo -e "  ${GREEN}Passed:${NC} $TESTS_PASSED"
    echo -e "  ${RED}Failed:${NC} $TESTS_FAILED"
    echo "========================================"

    if [ $TESTS_FAILED -gt 0 ]; then
        exit 1
    fi

    exit 0
}

main "$@"
