#!/bin/bash
BUILD_DIR=$(dirname "$0")/build
mkdir -p $BUILD_DIR
cd $BUILD_DIR

sum="sha1sum"

echo "If you need reproducible build, export GO111MODULE=on first"

if ! hash sha1sum 2>/dev/null; then
	if ! hash shasum 2>/dev/null; then
		echo "I can't see 'sha1sum' or 'shasum'"
		echo "Please install one of them!"
		exit
	fi
	sum="shasum"
fi

UPX=false

VERSION=`date -u +%Y%m%d`
LDFLAGS="-X main.VERSION=$VERSION -s -w"
GCFLAGS=""

# name:package for every binary in a release archive. kcptun_* are the KCP
# tunnel; udptun_* relay UDP as plain datagrams and share none of its machinery.
PKGS=(
	"kcptun_client github.com/xtaci/kcptun/client"
	"kcptun_server github.com/xtaci/kcptun/server"
	"udptun_client github.com/xtaci/kcptun/udpclient"
	"udptun_server github.com/xtaci/kcptun/udpserver"
)

# release <platform> [suffix] -- builds every binary for the GOOS/GOARCH
# already exported, then archives them. <platform> names the binaries
# (client_linux_amd64); its dashed form names the archive.
release() {
	local platform=$1 suffix=$2 names=()
	for pkg in "${PKGS[@]}"; do
		set -- $pkg
		go build -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -o $1_${platform}${suffix} $2 || return 1
		names+=("$1_${platform}${suffix}")
	done
	if $UPX; then upx -9 "${names[@]}"; fi
	local archive=kcptun-$(echo $platform | tr _ -)-$VERSION.tar.gz
	tar -zcf $archive "${names[@]}"
	$sum $archive
}

export CGO_ENABLED=0

# AMD64
for os in linux darwin windows freebsd; do
	suffix=""
	if [ "$os" == "windows" ]; then suffix=".exe"; fi
	GOOS=$os GOARCH=amd64 release ${os}_amd64 "$suffix"
done

# 386
for os in linux windows; do
	suffix=""
	if [ "$os" == "windows" ]; then suffix=".exe"; fi
	GOOS=$os GOARCH=386 release ${os}_386 "$suffix"
done

# ARM
for v in 5 6 7; do
	GOOS=linux GOARCH=arm GOARM=$v release linux_arm$v
done

# ARM64
GOOS=linux GOARCH=arm64 release linux_arm64

# MIPS32LE
GOOS=linux GOARCH=mipsle GOMIPS=softfloat release linux_mipsle
GOOS=linux GOARCH=mips GOMIPS=softfloat release linux_mips
