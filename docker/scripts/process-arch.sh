#!/bin/bash
# Process Arch Linux packages
set -e

REPO_DIR="${REPO_DATA_DIR:-/data/packages}/arch"
GPG_DIR="${REPO_GPG_DIR:-/data/gpg}"
REPO_NAME="custom"
ARCHITECTURES="x86_64 aarch64"

usage() {
    echo "Usage: process-arch <command> [options]"
    echo ""
    echo "Commands:"
    echo "  init                    Initialize empty repository"
    echo "  add <file.pkg.tar.*>    Add package to repository"
    echo "  remove <package>        Remove package from repository"
    echo "  rebuild                 Rebuild repository database"
    echo ""
}

init_repo() {
    echo "Initializing Arch Linux repository..."

    for arch in $ARCHITECTURES; do
        local arch_dir="$REPO_DIR/$arch"
        mkdir -p "$arch_dir"

        # Create empty repository database
        touch "$arch_dir/.empty"
        tar -czf "$arch_dir/$REPO_NAME.db.tar.gz" -C "$arch_dir" .empty
        rm "$arch_dir/.empty"
        ln -sf "$REPO_NAME.db.tar.gz" "$arch_dir/$REPO_NAME.db"

        # Create empty files database
        tar -czf "$arch_dir/$REPO_NAME.files.tar.gz" -T /dev/null 2>/dev/null || \
            tar -czf "$arch_dir/$REPO_NAME.files.tar.gz" --files-from=/dev/null
        ln -sf "$REPO_NAME.files.tar.gz" "$arch_dir/$REPO_NAME.files"
    done

    # Create pacman.conf snippet for clients
    cat > "$REPO_DIR/pacman.conf" <<EOF
# Add this to /etc/pacman.conf
[$REPO_NAME]
SigLevel = Optional TrustAll
Server = http://\$REPO_HOST/arch/\$arch
EOF

    echo "Arch Linux repository initialized."
}

add_package() {
    local pkg_file="$1"

    if [ ! -f "$pkg_file" ]; then
        echo "Error: File not found: $pkg_file"
        exit 1
    fi

    # Extract package info from filename
    # Format: name-version-release-arch.pkg.tar.zst
    local filename
    filename=$(basename "$pkg_file")
    local pkg_arch=""

    # Detect architecture from filename
    if [[ "$filename" == *"-x86_64."* ]]; then
        pkg_arch="x86_64"
    elif [[ "$filename" == *"-aarch64."* ]]; then
        pkg_arch="aarch64"
    elif [[ "$filename" == *"-any."* ]]; then
        # 'any' architecture - add to all
        pkg_arch="any"
    else
        echo "Warning: Could not detect architecture, assuming x86_64"
        pkg_arch="x86_64"
    fi

    echo "Adding package: $filename"

    if [ "$pkg_arch" = "any" ]; then
        # Add to all architectures
        for arch in $ARCHITECTURES; do
            local arch_dir="$REPO_DIR/$arch"
            mkdir -p "$arch_dir"
            cp "$pkg_file" "$arch_dir/"

            # Add to repository database
            repo-add "$arch_dir/$REPO_NAME.db.tar.gz" "$arch_dir/$filename"
        done
    else
        local arch_dir="$REPO_DIR/$pkg_arch"
        mkdir -p "$arch_dir"
        cp "$pkg_file" "$arch_dir/"

        # Add to repository database
        repo-add "$arch_dir/$REPO_NAME.db.tar.gz" "$arch_dir/$filename"
    fi

    # Sign if GPG key exists
    sign_repo

    echo "Package added successfully."
}

remove_package() {
    local pkg_name="$1"

    echo "Removing package: $pkg_name"

    for arch in $ARCHITECTURES; do
        local arch_dir="$REPO_DIR/$arch"
        if [ -d "$arch_dir" ]; then
            # Remove from database
            repo-remove "$arch_dir/$REPO_NAME.db.tar.gz" "$pkg_name" 2>/dev/null || true

            # Remove package files
            find "$arch_dir" -name "${pkg_name}-*.pkg.tar.*" -delete 2>/dev/null || true
        fi
    done

    sign_repo

    echo "Package removed successfully."
}

rebuild_repo() {
    echo "Rebuilding Arch Linux repository..."

    for arch in $ARCHITECTURES; do
        local arch_dir="$REPO_DIR/$arch"
        if [ -d "$arch_dir" ]; then
            # Remove existing database
            rm -f "$arch_dir/$REPO_NAME.db"* "$arch_dir/$REPO_NAME.files"*

            # Rebuild from packages
            local packages
            packages=$(find "$arch_dir" -name "*.pkg.tar.*" -not -name "*.sig" 2>/dev/null)
            if [ -n "$packages" ]; then
                repo-add "$arch_dir/$REPO_NAME.db.tar.gz" $packages
            else
                # Create empty database
                touch "$arch_dir/.empty"
                tar -czf "$arch_dir/$REPO_NAME.db.tar.gz" -C "$arch_dir" .empty
                rm "$arch_dir/.empty"
            fi

            ln -sf "$REPO_NAME.db.tar.gz" "$arch_dir/$REPO_NAME.db"
            ln -sf "$REPO_NAME.files.tar.gz" "$arch_dir/$REPO_NAME.files" 2>/dev/null || true
        fi
    done

    sign_repo

    echo "Repository rebuilt."
}

sign_repo() {
    if [ -f "$GPG_DIR/key-id" ]; then
        GPG_KEY_ID=$(cat "$GPG_DIR/key-id")

        for arch in $ARCHITECTURES; do
            local arch_dir="$REPO_DIR/$arch"
            if [ -d "$arch_dir" ]; then
                # Sign database
                rm -f "$arch_dir/$REPO_NAME.db.tar.gz.sig"
                gpg --default-key "$GPG_KEY_ID" --detach-sign "$arch_dir/$REPO_NAME.db.tar.gz" 2>/dev/null || true
            fi
        done
    fi
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
