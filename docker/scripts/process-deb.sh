#!/bin/bash
# Process Debian/Ubuntu .deb packages
set -e

REPO_DIR="${REPO_DATA_DIR:-/data/packages}/deb"
GPG_DIR="${REPO_GPG_DIR:-/data/gpg}"
DISTS="stable"
COMPONENTS="main"
ARCHITECTURES="amd64 arm64"

usage() {
    echo "Usage: process-deb <command> [options]"
    echo ""
    echo "Commands:"
    echo "  init                    Initialize empty repository"
    echo "  add <file.deb> [dist]   Add package to repository"
    echo "  remove <package> [dist] Remove package from repository"
    echo "  rebuild [dist]          Rebuild repository metadata"
    echo ""
}

init_repo() {
    echo "Initializing APT repository..."

    for dist in $DISTS; do
        for comp in $COMPONENTS; do
            for arch in $ARCHITECTURES; do
                dir="$REPO_DIR/dists/$dist/$comp/binary-$arch"
                mkdir -p "$dir"

                # Create empty Packages file
                touch "$dir/Packages"
                gzip -kf "$dir/Packages"
            done
        done

        # Create Release file
        create_release "$dist"
    done

    echo "APT repository initialized."
}

create_release() {
    local dist="$1"
    local dist_dir="$REPO_DIR/dists/$dist"

    # Generate Release file
    cat > "$dist_dir/Release" <<EOF
Origin: Package Repository
Label: Package Repository
Suite: $dist
Codename: $dist
Architectures: $ARCHITECTURES
Components: $COMPONENTS
Description: Custom Package Repository
Date: $(date -Ru)
EOF

    # Add checksums for all files
    cd "$dist_dir"

    echo "MD5Sum:" >> Release
    find . -name "Packages*" -o -name "Sources*" 2>/dev/null | while read file; do
        if [ -f "$file" ]; then
            size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file")
            md5=$(md5sum "$file" | cut -d' ' -f1)
            echo " $md5 $size ${file#./}" >> Release
        fi
    done

    echo "SHA256:" >> Release
    find . -name "Packages*" -o -name "Sources*" 2>/dev/null | while read file; do
        if [ -f "$file" ]; then
            size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file")
            sha256=$(sha256sum "$file" | cut -d' ' -f1)
            echo " $sha256 $size ${file#./}" >> Release
        fi
    done

    cd - > /dev/null

    # Sign the Release file
    if [ -f "$GPG_DIR/key-id" ]; then
        GPG_KEY_ID=$(cat "$GPG_DIR/key-id")
        rm -f "$dist_dir/Release.gpg" "$dist_dir/InRelease"
        gpg --default-key "$GPG_KEY_ID" --armor --detach-sign -o "$dist_dir/Release.gpg" "$dist_dir/Release"
        gpg --default-key "$GPG_KEY_ID" --armor --clearsign -o "$dist_dir/InRelease" "$dist_dir/Release"
    fi
}

add_package() {
    local deb_file="$1"
    local dist="${2:-stable}"

    if [ ! -f "$deb_file" ]; then
        echo "Error: File not found: $deb_file"
        exit 1
    fi

    # Extract package info
    local pkg_name
    pkg_name=$(dpkg-deb -f "$deb_file" Package)
    local pkg_arch
    pkg_arch=$(dpkg-deb -f "$deb_file" Architecture)
    local pkg_version
    pkg_version=$(dpkg-deb -f "$deb_file" Version)

    echo "Adding package: $pkg_name ($pkg_version) for $pkg_arch"

    # Map architecture
    case "$pkg_arch" in
        amd64|x86_64) pkg_arch="amd64" ;;
        arm64|aarch64) pkg_arch="arm64" ;;
        all) pkg_arch="all" ;;
        *) echo "Warning: Unknown architecture $pkg_arch" ;;
    esac

    # Copy to pool
    local pool_dir="$REPO_DIR/pool/main/${pkg_name:0:1}/$pkg_name"
    mkdir -p "$pool_dir"
    cp "$deb_file" "$pool_dir/"

    # Rebuild repository
    rebuild_repo "$dist"

    echo "Package added successfully."
}

remove_package() {
    local pkg_name="$1"
    local dist="${2:-stable}"

    echo "Removing package: $pkg_name"

    # Remove from pool
    local pool_dir="$REPO_DIR/pool/main/${pkg_name:0:1}/$pkg_name"
    if [ -d "$pool_dir" ]; then
        rm -rf "$pool_dir"
    fi

    # Rebuild repository
    rebuild_repo "$dist"

    echo "Package removed successfully."
}

rebuild_repo() {
    local dist="${1:-stable}"

    echo "Rebuilding APT repository for $dist..."

    for comp in $COMPONENTS; do
        for arch in $ARCHITECTURES; do
            local binary_dir="$REPO_DIR/dists/$dist/$comp/binary-$arch"
            mkdir -p "$binary_dir"

            # Generate Packages file using dpkg-scanpackages
            cd "$REPO_DIR"
            dpkg-scanpackages --arch "$arch" pool/ > "$binary_dir/Packages" 2>/dev/null || true

            # Also include 'all' architecture packages
            if [ "$arch" != "all" ]; then
                dpkg-scanpackages --arch all pool/ >> "$binary_dir/Packages" 2>/dev/null || true
            fi

            gzip -kf "$binary_dir/Packages"
            cd - > /dev/null
        done
    done

    # Recreate Release file
    create_release "$dist"

    echo "Repository rebuilt."
}

# Main
case "${1:-}" in
    init)
        init_repo
        ;;
    add)
        add_package "$2" "$3"
        ;;
    remove)
        remove_package "$2" "$3"
        ;;
    rebuild)
        rebuild_repo "$2"
        ;;
    *)
        usage
        exit 1
        ;;
esac
