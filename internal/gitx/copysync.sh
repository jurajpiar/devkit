# devkit's copy sync, the VM's side. Runs as the sandbox user (and in
# tests, on a Mac, with a temporary HOME), so it keeps to bash 3.2 and to
# what BSD and GNU tools share.
#
# Arguments: workspace, pack ("" when the VM has every object), manifest,
# the incoming snapshot's commit id, and 1 to take the Mac's version of the
# files in conflict. Prints lines the Mac reads:
#   devkit-conflict <path>   changed in the VM and by this snapshot
#   devkit-kept <path>       differs from the snapshot after the sync
#   devkit-skip <path>       a manifest entry left alone
#   devkit-error <text>
#   devkit-synced <commit>
# Paths are git's C-quoted form, one line each. Exits 3 on a conflict,
# having changed nothing in the workspace.
set -u
umask 022
for v in $(compgen -e); do
  case $v in GIT_* | LC_* | LANG) unset "$v" ;; esac
done
export LC_ALL=C GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0

ws=$1 pack=$2 manifest=$3 incoming=$4 overwrite=$5
repo=$HOME/.local/state/devkit/sync.git
empty=4b825dc642cb6eb9a060e54bf8d69288fbee4904

tmp=$(mktemp -d "${TMPDIR:-/tmp}/devkit-sync.XXXXXX") || exit 1
cleanup() {
  rm -rf "$tmp"
  if [ -n "$pack" ]; then rm -f "$pack"; fi
  if [ -n "$manifest" ]; then rm -f "$manifest"; fi
}
trap cleanup EXIT
fail() { echo "devkit-error $*"; exit 1; }
# r is the private repository; g the same with the workspace as work tree.
r() { git -c core.hooksPath=/dev/null --git-dir="$repo" "$@"; }
g() { git -c core.hooksPath=/dev/null --git-dir="$repo" --work-tree="$ws" "$@"; }
# t works on a scratch index, to compare files with the snapshot's
# versions without touching the real one.
t() { GIT_INDEX_FILE="$tmp/index" g "$@"; }
# Sets of paths, C-quoted and one a line, so a line is a path. The first
# file is read whole before the second, even when it is empty.
#   both A B: the lines of B that are also in A
#   pick A INFO / omit A INFO: the index-info lines of INFO whose path is,
#   or is not, in A
both() { awk 'BEGIN { while ((getline l < ARGV[1]) > 0) a[l]; ARGV[1] = "" } ($0 in a)' "$1" "$2"; }
pick() { awk -F '\t' 'BEGIN { while ((getline l < ARGV[1]) > 0) a[l]; ARGV[1] = "" } ($2 in a)' "$1" "$2"; }
omit() { awk -F '\t' 'BEGIN { while ((getline l < ARGV[1]) > 0) a[l]; ARGV[1] = "" } !($2 in a)' "$1" "$2"; }

case $incoming in *[!0-9a-f]* | '') fail "not a commit id: $incoming" ;; esac
[ ${#incoming} -eq 40 ] || fail "not a commit id: $incoming"

if [ ! -f "$repo/HEAD" ]; then
  mkdir -p "$repo" && git -c init.templateDir= init -q --bare --object-format=sha1 "$repo" >/dev/null ||
    fail "could not create $repo"
fi
# Only plain files: no line endings, filters or encodings, whatever the
# project's .gitattributes ask for. info/attributes outranks it.
mkdir -p "$repo/info" &&
  printf '* -text -eol -ident -filter -working-tree-encoding\n' >"$repo/info/attributes" || fail "could not write $repo/info/attributes"
# A Linux work tree; a changed inode time alone is not a change.
for kv in core.trustctime=false core.filemode=true core.symlinks=true core.ignorecase=false \
  core.precomposeunicode=false core.protectNTFS=false core.protectHFS=false core.autocrlf=false \
  core.quotePath=true core.untrackedCache=false core.fsmonitor=false core.splitIndex=false gc.auto=0; do
  r config "${kv%%=*}" "${kv#*=}" || fail "could not configure $repo"
done

# A workspace that is gone starts again from nothing.
if [ ! -d "$ws" ]; then
  r update-ref -d refs/devkit/synced 2>/dev/null
  mkdir -p "$ws" || fail "could not create $ws"
fi
cd "$ws" || fail "could not enter $ws"

if [ -n "$pack" ]; then
  r index-pack --stdin <"$pack" >/dev/null 2>"$tmp/err" || fail "could not take the snapshot: $(head -c 300 "$tmp/err" | tr '\n' ' ')"
fi
r cat-file -e "$incoming^{commit}" 2>/dev/null || fail "the snapshot $incoming did not arrive"

synced=$(r rev-parse -q --verify 'refs/devkit/synced^{commit}' 2>/dev/null) || synced=
if [ -z "$synced" ]; then
  # First sync into this workspace: whatever is there is compared with
  # the snapshot, nothing is assumed.
  old=$empty
  rm -f "$repo/index"
else
  old=$synced
  [ -f "$repo/index" ] || r read-tree "$old" || fail "could not read the last snapshot"
fi

# A timestamp alone must not count as a change.
g update-index -q --refresh >/dev/null 2>&1

# What the VM changed since the last snapshot (not counting deletions,
# which the merge restores if the Mac changed the file), what the Mac
# deleted and what it added.
g diff-files --name-only --diff-filter=d >"$tmp/vm" || fail "could not compare the workspace"
g diff-tree -r --no-renames --name-only --diff-filter=D "$old" "$incoming" >"$tmp/del" || fail "could not compare snapshots"
g diff-tree -r --no-renames --name-only --diff-filter=A "$old" "$incoming" >"$tmp/add" || fail "could not compare snapshots"
# Every path the Mac added or changed, as index entries of its new
# version, compared with the workspace in a scratch index.
g diff-tree -r --no-renames --diff-filter=d "$old" "$incoming" |
  awk -F '\t' '{ split($1, f, " "); print f[2] " " f[4] "\t" $2 }' >"$tmp/new.info" || fail "could not compare snapshots"
t update-index --index-info <"$tmp/new.info" || fail "could not compare the workspace"
t update-index -q --refresh >/dev/null 2>&1
t diff-files --name-status >"$tmp/cmp" || fail "could not compare the workspace"
awk -F '\t' '$1 != "D" { print $2 }' "$tmp/cmp" >"$tmp/differ"   # there, and not the Mac's version
awk -F '\t' '$1 == "D" { print $2 }' "$tmp/cmp" >"$tmp/missing"

# In conflict: a file the VM changed that the Mac deleted; and a file the
# Mac added or changed that is in the workspace, differs from the Mac's,
# and is not simply the last snapshot's (changed in the VM, or never part
# of a snapshot). A file already equal to the Mac's version is not.
both "$tmp/vm" "$tmp/del" >"$tmp/c-del"
cat "$tmp/vm" "$tmp/add" >"$tmp/vm+add"
both "$tmp/vm+add" "$tmp/differ" >"$tmp/c-new"
cat "$tmp/c-del" "$tmp/c-new" | sort -u >"$tmp/conflicts"

if [ -s "$tmp/conflicts" ] && [ "$overwrite" != 1 ]; then
  sed 's/^/devkit-conflict /' "$tmp/conflicts"
  exit 3
fi
if [ "$overwrite" = 1 ]; then
  # The Mac's version of exactly these: back to the last snapshot's for
  # the merge to delete, or the Mac's own version written now.
  if [ -s "$tmp/c-del" ]; then
    g checkout-index -f -u --stdin <"$tmp/c-del" || fail "could not reset the files in conflict"
  fi
  if [ -s "$tmp/c-new" ]; then
    pick "$tmp/c-new" "$tmp/new.info" | g update-index --index-info &&
      g checkout-index -f -u --stdin <"$tmp/c-new" || fail "could not reset the files in conflict"
  fi
fi
# Files already as the Mac has them are taken as they are, so the merge
# does not refuse to overwrite them and nothing is rewritten.
cat "$tmp/differ" "$tmp/missing" >"$tmp/not-same"
omit "$tmp/not-same" "$tmp/new.info" | g update-index --index-info ||
  fail "could not record the files that already match"
g update-index -q --refresh >/dev/null 2>&1

if ! g read-tree -m -u "$old" "$incoming" 2>"$tmp/err"; then
  head -n 20 "$tmp/err" | sed 's/^/devkit-error /'
  exit 1
fi
r update-ref refs/devkit/synced "$incoming" || fail "could not record the snapshot"

# inside P: P is a relative path in the workspace (the current directory)
# with no ., .., empty or .git component, and nothing on the way to it,
# itself included, is a symlink, so nothing below acts outside the
# workspace.
inside() {
  local rest=$1 part cur=
  case $rest in '' | /* | */) return 1 ;; esac
  while :; do
    case $rest in
      */*) part=${rest%%/*} rest=${rest#*/} ;;
      *) part=$rest rest= ;;
    esac
    case $part in '' | . | .. | [.][gG][iI][tT]) return 1 ;; esac
    cur=${cur:+$cur/}$part
    [ -L "$cur" ] && return 1
    [ -z "$rest" ] && return 0
  done
}
# What git cannot carry: directories, empty ones too, and modes.
if [ -n "$manifest" ]; then
  while IFS= read -r -d '' rec; do
    kind=${rec:0:1} mode=${rec:1:4} p=${rec:6}
    case $mode in [0-7][0-7][0-7][0-7]) ;; *) kind=bad ;; esac
    if [ "${rec:5:1}" != " " ] || ! inside "$p"; then
      printf 'devkit-skip %q\n' "$p"
      continue
    fi
    case $kind in
      r) if [ -d "$p" ]; then rmdir -- "$p" 2>/dev/null; fi ;;
      d) { [ -d "$p" ] || mkdir -p -- "$p"; } && chmod -- "$mode" "$p" || printf 'devkit-skip %q\n' "$p" ;;
      f) if [ -f "$p" ]; then chmod -- "$mode" "$p" || printf 'devkit-skip %q\n' "$p"; fi ;;
      *) printf 'devkit-skip %q\n' "$p" ;;
    esac
  done <"$manifest"
fi

g update-index -q --refresh >/dev/null 2>&1
g diff-files --name-only | sed 's/^/devkit-kept /'
# One snapshot is kept: what the last one had and this one does not goes.
if [ -n "$pack" ]; then
  r repack -a -d -q >/dev/null 2>&1 && r prune --expire=now >/dev/null 2>&1
fi
echo "devkit-synced $incoming"
