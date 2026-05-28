#!/bin/sh
set -eu

repo="tuannvm/okta-awscli-rs"
bin="okta-awscli-rs"
install_dir="${INSTALL_DIR:-$HOME/.local/bin}"
version="${OKTA_AWSCLI_RS_VERSION:-latest}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: required command not found: $1" >&2
    exit 1
  }
}

need curl
need tar

os="$(uname -s)"
arch="$(uname -m)"
case "$os:$arch" in
  Darwin:arm64) target="aarch64-apple-darwin" ;;
  Darwin:x86_64) target="x86_64-apple-darwin" ;;
  Linux:x86_64) target="x86_64-unknown-linux-gnu" ;;
  *)
    echo "error: unsupported platform: $os $arch" >&2
    exit 1
    ;;
esac

if [ "$version" = "latest" ]; then
  base_url="https://github.com/$repo/releases/latest/download"
  label="latest"
else
  case "$version" in
    v*) tag="$version" ;;
    *) tag="v$version" ;;
  esac
  base_url="https://github.com/$repo/releases/download/$tag"
  label="$tag"
fi

if [ "$version" = "latest" ]; then
  latest_url="https://api.github.com/repos/$repo/releases/latest"
  resolved="$(curl -fsSL "$latest_url" | sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p' | head -n 1)"
  if [ -z "$resolved" ]; then
    echo "error: could not resolve latest release version" >&2
    exit 1
  fi
  asset="$bin-$resolved-$target.tar.gz"
else
  asset="$bin-${tag#v}-$target.tar.gz"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "Downloading $repo $label for $target..."
curl -fL "$base_url/$asset" -o "$tmp/$asset"
curl -fL "$base_url/SHA256SUMS" -o "$tmp/SHA256SUMS"

(
  cd "$tmp"
  if command -v sha256sum >/dev/null 2>&1; then
    grep "  $asset$" SHA256SUMS | sha256sum -c -
  elif command -v shasum >/dev/null 2>&1; then
    grep "  $asset$" SHA256SUMS | shasum -a 256 -c -
  else
    echo "error: sha256sum or shasum is required for checksum verification" >&2
    exit 1
  fi
  tar -xzf "$asset"
)

mkdir -p "$install_dir"
cp "$tmp/${asset%.tar.gz}/$bin" "$install_dir/$bin"
chmod 755 "$install_dir/$bin"

echo "Installed $bin to $install_dir/$bin"
case ":$PATH:" in
  *":$install_dir:"*) ;;
  *) echo "Add $install_dir to PATH to run $bin from any shell." ;;
esac
