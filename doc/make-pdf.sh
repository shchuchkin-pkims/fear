#!/usr/bin/env bash
# Собрать PDF-версии документации из Markdown:
#
#   doc/manual.md          -> doc/manual.pdf
#   doc/how-it-works.md    -> doc/how-it-works.pdf
#   doc/how-it-works.ru.md -> doc/how-it-works.ru.pdf
#
# Нужны pandoc и Chrome/Chromium: pandoc делает HTML с вшитыми картинками
# (doc/pdf.css), браузер печатает его в PDF. Схемы «Как устроен» сначала
# пересобираются из doc/images/how-it-works/make.py.
#
# usage: doc/make-pdf.sh [file.md ...]     (без аргументов - все три)
set -euo pipefail

DOC=$(cd "$(dirname "$0")" && pwd)
cd "$DOC"

CHROME=""
for c in google-chrome chromium chromium-browser; do
    if command -v "$c" >/dev/null 2>&1; then CHROME=$c; break; fi
done
[ -n "$CHROME" ] || { echo "Chrome/Chromium not found" >&2; exit 1; }
command -v pandoc >/dev/null 2>&1 || { echo "pandoc not found" >&2; exit 1; }

python3 images/how-it-works/make.py >/dev/null

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

build() {
    local md=$1 title lang
    title=$(sed -n 's/^# //p' "$md" | head -1)
    case "$md" in *.ru.md) lang=ru ;; *) lang=en ;; esac
    local out=${md%.md}.pdf
    pandoc "$md" -f gfm -t html5 -s \
        --metadata pagetitle="$title" --metadata lang="$lang" \
        --css "$DOC/pdf.css" --embed-resources --resource-path="$DOC" \
        -o "$TMP/page.html"
    "$CHROME" --headless=new --disable-gpu --no-sandbox \
        --user-data-dir="$TMP/chrome" --no-pdf-header-footer \
        --print-to-pdf="$DOC/$out" "file://$TMP/page.html" >/dev/null 2>&1
    echo "$out"
}

if [ $# -eq 0 ]; then
    set -- manual.md how-it-works.md how-it-works.ru.md
fi
for md in "$@"; do
    build "$(basename "$md")"
done
