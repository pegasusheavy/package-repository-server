#!/bin/bash
# Process RPM packages for YUM/DNF repositories
set -e

REPO_DIR="${REPO_DATA_DIR:-/data/packages}/rpm"
GPG_DIR="${REPO_GPG_DIR:-/data/gpg}"
ARCHITECTURES="x86_64 aarch64"

usage() {
    echo "Usage: process-rpm <command> [options]"
    echo ""
    echo "Commands:"
    echo "  init                  Initialize empty repository"
    echo "  add <file.rpm>        Add package to repository"
    echo "  remove <package>      Remove package from repository"
    echo "  rebuild               Rebuild repository metadata"
    echo ""
}

init_repo() {
    echo "Initializing RPM repository..."

    for arch in $ARCHITECTURES; do
        local arch_dir="$REPO_DIR/$arch"
        mkdir -p "$arch_dir"

        # Create initial repository metadata
        createrepo_c "$arch_dir"
    done

    # Create repo configuration file for clients
    cat > "$REPO_DIR/package-repo.repo" <<EOF
[package-repo]
name=Package Repository
baseurl=http://\$REPO_HOST/rpm/\$basearch/
enabled=1
gpgcheck=1
gpgkey=http://\$REPO_HOST/repo.gpg
EOF

    echo "RPM repository initialized."
}

add_package() {
    local rpm_file="$1"

    if [ ! -f "$rpm_file" ]; then
        echo "Error: File not found: $rpm_file"
        exit 1
    fi

    # Extract package info
    local pkg_name
    pkg_name=$(rpm -qp --queryformat '%{NAME}' "$rpm_file" 2>/dev/null)
    local pkg_arch
    pkg_arch=$(rpm -qp --queryformat '%{ARCH}' "$rpm_file" 2>/dev/null)
    local pkg_version
    pkg_version=$(rpm -qp --queryformat '%{VERSION}-%{RELEASE}' "$rpm_file" 2>/dev/null)

    echo "Adding package: $pkg_name ($pkg_version) for $pkg_arch"

    # Map architecture
    case "$pkg_arch" in
        x86_64|amd64) pkg_arch="x86_64" ;;
        aarch64|arm64) pkg_arch="aarch64" ;;
        noarch)
            # Copy to all architectures
            for arch in $ARCHITECTURES; do
                local arch_dir="$REPO_DIR/$arch"
                mkdir -p "$arch_dir"
                cp "$rpm_file" "$arch_dir/"
            done
            rebuild_repo
            echo "Package added successfully."
            return
            ;;
        *)
            echo "Warning: Unknown architecture $pkg_arch, using x86_64"
            pkg_arch="x86_64"
            ;;
    esac

    # Copy to architecture directory
    local arch_dir="$REPO_DIR/$pkg_arch"
    mkdir -p "$arch_dir"
    cp "$rpm_file" "$arch_dir/"

    # Sign the RPM if GPG key exists
    if [ -f "$GPG_DIR/key-id" ]; then
        GPG_KEY_ID=$(cat "$GPG_DIR/key-id")
        rpm --addsign "$arch_dir/$(basename "$rpm_file")" 2>/dev/null || true
    fi

    # Rebuild repository
    rebuild_repo

    echo "Package added successfully."
}

remove_package() {
    local pkg_pattern="$1"

    echo "Removing packages matching: $pkg_pattern"

    for arch in $ARCHITECTURES; do
        local arch_dir="$REPO_DIR/$arch"
        if [ -d "$arch_dir" ]; then
            find "$arch_dir" -name "${pkg_pattern}*.rpm" -delete 2>/dev/null || true
        fi
    done

    rebuild_repo

    echo "Package removed successfully."
}

rebuild_repo() {
    echo "Rebuilding RPM repository..."

    for arch in $ARCHITECTURES; do
        local arch_dir="$REPO_DIR/$arch"
        if [ -d "$arch_dir" ]; then
            # Update repository metadata
            createrepo_c --update "$arch_dir"

            # Sign repository metadata if GPG key exists
            if [ -f "$GPG_DIR/key-id" ]; then
                GPG_KEY_ID=$(cat "$GPG_DIR/key-id")
                rm -f "$arch_dir/repodata/repomd.xml.asc"
                gpg --default-key "$GPG_KEY_ID" --armor --detach-sign "$arch_dir/repodata/repomd.xml"
            fi
        fi
    done

    echo "Repository rebuilt."
}

# Main
case "${1:-}" in
    init)
        init_repo
        ;;
    add)
        add_package "$2"
        ;;
    remove)
        remove_package "$2"
        ;;
    rebuild)
        rebuild_repo
        ;;
    *)
        usage
        exit 1
        ;;
esac
