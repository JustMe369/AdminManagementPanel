#!/bin/bash
# Enhanced installation script with security checks

# Add security validation functions
validate_path() {
    local path="$1"
    if [[ "$path" != /* ]]; then
        echo "Error: Path must be absolute"
        exit 1
    fi
    if [[ "$path" =~ \.\. ]]; then
        echo "Error: Path must not contain '..'"
        exit 1
    fi
}

check_dependencies() {
    local missing=()
    for dep in "$@"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        echo "Missing dependencies: ${missing[*]}"
        exit 1
    fi
}

# Add security checks
validate_path "$INSTALL_DIR"
validate_path "$WEB_DIR"
check_dependencies python3 sqlite3 iptables

# Add checksum verification for critical files
verify_checksum() {
    local file="$1"
    local expected_checksum="$2"
    
    if [ ! -f "$file" ]; then
        echo "Error: File $file not found"
        exit 1
    fi
    
    actual_checksum=$(sha256sum "$file" | cut -d' ' -f1)
    if [ "$actual_checksum" != "$expected_checksum" ]; then
        echo "Error: Checksum verification failed for $file"
        exit 1
    fi
}