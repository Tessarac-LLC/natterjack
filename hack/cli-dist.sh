#!/usr/bin/env bash
# Builds the natterjack CLI for every supported OS and architecture and packs
# each into an archive with the LICENSE and NOTICE. Archives are
# reproducible: the same commit and VERSION give byte-identical files, with
# every timestamp set to the commit time.
#
# Usage: VERSION=v1.2.3 OUT=dist hack/cli-dist.sh
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
: "${VERSION:?VERSION is required, for example v1.2.3}"
: "${OUT:?OUT is required}"
mkdir -p "$OUT"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
epoch="$(git -C "$root" log -1 --format=%ct)"

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
	os="${target%/*}" arch="${target#*/}"
	exe=natterjack
	[[ "$os" == windows ]] && exe=natterjack.exe
	dir="$work/$os-$arch"
	mkdir -p "$dir"
	(cd "$root" && GOWORK=off CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false \
		-ldflags "-s -w -buildid= -X github.com/Tessarac-LLC/natterjack/internal/version.Version=$VERSION" \
		-o "$dir/$exe" ./cmd/natterjack)
	cp "$root/LICENSE" "$root/NOTICE" "$dir/"
	name="natterjack_${VERSION}_${os}_${arch}"
	python3 -I - "$dir" "$OUT" "$name" "$os" "$exe" "$epoch" <<'PY'
import gzip, io, os, sys, tarfile, zipfile
src, out, name, goos, exe, epoch = sys.argv[1:7]
epoch = int(epoch)
files = [exe, "LICENSE", "NOTICE"]
def mode(f):
    return 0o755 if f == exe else 0o644
if goos == "windows":
    import time
    stamp = time.gmtime(max(epoch, 315532800))[:6]
    with zipfile.ZipFile(os.path.join(out, name + ".zip"), "w", zipfile.ZIP_DEFLATED) as z:
        for f in files:
            info = zipfile.ZipInfo(f"{name}/{f}", stamp)
            info.external_attr = (0o100000 | mode(f)) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, open(os.path.join(src, f), "rb").read())
else:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as t:
        for f in files:
            info = t.gettarinfo(os.path.join(src, f), f"{name}/{f}")
            info.mtime, info.mode = epoch, mode(f)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.pax_headers = {}
            with open(os.path.join(src, f), "rb") as fh:
                t.addfile(info, fh)
    with open(os.path.join(out, name + ".tar.gz"), "wb") as fh:
        with gzip.GzipFile(filename="", mode="wb", fileobj=fh, mtime=epoch, compresslevel=9) as g:
            g.write(buf.getvalue())
PY
	echo "cli $os/$arch"
done
