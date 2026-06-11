#!/bin/bash
# Process Alpine Linux APK packages
set -e

REPO_DIR="${REPO_DATA_DIR:-/data/packages}/alpine"
GPG_DIR="${REPO_GPG_DIR:-/data/gpg}"
ALPINE_VERSION="v3.19"
REPO_NAME="main"
ARCHITECTURES="x86_64 aarch64"

usage() {
    echo "Usage: process-alpine <command> [options]"
    echo ""
    echo "Commands:"
    echo "  init                  Initialize empty repository"
    echo "  add <file.apk>        Add package to repository"
    echo "  remove <package>      Remove package from repository"
    echo "  rebuild               Rebuild APKINDEX"
    echo ""
}

init_repo() {
    echo "Initializing Alpine Linux repository..."

    for arch in $ARCHITECTURES; do
        local arch_dir="$REPO_DIR/$ALPINE_VERSION/$REPO_NAME/$arch"
        mkdir -p "$arch_dir"

        # Create empty APKINDEX
        create_apkindex "$arch_dir"
    done

    # Create repository configuration for clients
    cat > "$REPO_DIR/repositories" <<EOF
# Add this line to /etc/apk/repositories
http://\$REPO_HOST/alpine/$ALPINE_VERSION/$REPO_NAME
EOF

    echo "Alpine Linux repository initialized."
}

create_apkindex() {
    local arch_dir="$1"

    # Find all APK files
    local apk_files
    apk_files=$(find "$arch_dir" -maxdepth 1 -name "*.apk" 2>/dev/null)

    # Create APKINDEX
    cd "$arch_dir"

    if [ -n "$apk_files" ]; then
        # Generate index from packages
        local index_content=""
        for apk in *.apk; do
            [ -f "$apk" ] || continue

            # Extract package info
            local pkg_info
            pkg_info=$(tar -xzf "$apk" -O .PKGINFO 2>/dev/null || true)
            if [ -n "$pkg_info" ]; then
                index_content+="$pkg_info"
                index_content+=$'\n\n'
            fi
        done

        if [ -n "$index_content" ]; then
            echo "$index_content" > APKINDEX
        else
            touch APKINDEX
        fi
    else
        touch APKINDEX
    fi

    # Compress the index
    rm -f APKINDEX.tar.gz
    tar -czf APKINDEX.tar.gz APKINDEX
    rm -f APKINDEX

    # Sign if key exists
    if [ -f "$GPG_DIR/key-id" ]; then
        sign_apkindex "$arch_dir"
    fi

    cd - > /dev/null
}

sign_apkindex() {
    local arch_dir="$1"

    if [ -f "$GPG_DIR/private.key" ]; then
        cd "$arch_dir"

        # Create signature using openssl (Alpine style)
        # Note: In production, you'd use abuild-sign with proper Alpine keys
        openssl dgst -sha256 -sign "$GPG_DIR/private.key" -out .SIGN.RSA.repo.rsa.pub APKINDEX.tar.gz 2>/dev/null || true

        if [ -f ".SIGN.RSA.repo.rsa.pub" ]; then
            # Prepend signature to tarball
            mv APKINDEX.tar.gz APKINDEX.unsigned.tar.gz
            tar -czf APKINDEX.tar.gz .SIGN.RSA.repo.rsa.pub
            cat APKINDEX.unsigned.tar.gz >> APKINDEX.tar.gz 2>/dev/null || \
                mv APKINDEX.unsigned.tar.gz APKINDEX.tar.gz
            rm -f APKINDEX.unsigned.tar.gz .SIGN.RSA.repo.rsa.pub
        fi

        cd - > /dev/null
    fi
}

add_package() {
    local apk_file="$1"

    if [ ! -f "$apk_file" ]; then
        echo "Error: File not found: $apk_file"
        exit 1
    fi

    # Extract architecture from package
    local pkg_arch
    pkg_arch=$(tar -xzf "$apk_file" -O .PKGINFO 2>/dev/null | grep "^arch" | cut -d= -f2 | tr -d ' ')
    local pkg_name
    pkg_name=$(tar -xzf "$apk_file" -O .PKGINFO 2>/dev/null | grep "^pkgname" | cut -d= -f2 | tr -d ' ')
    local pkg_ver
    pkg_ver=$(tar -xzf "$apk_file" -O .PKGINFO 2>/dev/null | grep "^pkgver" | cut -d= -f2 | tr -d ' ')

    echo "Adding package: $pkg_name ($pkg_ver) for $pkg_arch"

    # Map architecture
    case "$pkg_arch" in
        x86_64|amd64) pkg_arch="x86_64" ;;
        aarch64|arm64) pkg_arch="aarch64" ;;
        noarch)
            # Add to all architectures
            for arch in $ARCHITECTURES; do
                local arch_dir="$REPO_DIR/$ALPINE_VERSION/$REPO_NAME/$arch"
                mkdir -p "$arch_dir"
                cp "$apk_file" "$arch_dir/"
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

    local arch_dir="$REPO_DIR/$ALPINE_VERSION/$REPO_NAME/$pkg_arch"
    mkdir -p "$arch_dir"
    cp "$apk_file" "$arch_dir/"

    # Rebuild index
    create_apkindex "$arch_dir"

    echo "Package added successfully."
}

remove_package() {
    local pkg_name="$1"

    echo "Removing package: $pkg_name"

    for arch in $ARCHITECTURES; do
        local arch_dir="$REPO_DIR/$ALPINE_VERSION/$REPO_NAME/$arch"
        if [ -d "$arch_dir" ]; then
            find "$arch_dir" -name "${pkg_name}-*.apk" -delete 2>/dev/null || true
            create_apkindex "$arch_dir"
        fi
    done

    echo "Package removed successfully."
}

rebuild_repo() {
    echo "Rebuilding Alpine Linux repository..."

    for arch in $ARCHITECTURES; do
        local arch_dir="$REPO_DIR/$ALPINE_VERSION/$REPO_NAME/$arch"
        if [ -d "$arch_dir" ]; then
            create_apkindex "$arch_dir"
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
