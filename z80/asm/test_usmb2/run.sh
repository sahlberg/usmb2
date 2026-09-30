#!/bin/sh
# Differential test: build the harness against the C usmb2.c and against
# the hand-written usmb2.asm for every feature combination, run both in
# z88dk-ticks and diff the outputs.
#
# usage: ./run.sh            (all configs)
#        ./run.sh c|asm NAME "FLAGS"   (single build+run, output to stdout)

export PATH=/data/sahlberg/z88dk/bin:$PATH
export ZCCCFG=/data/sahlberg/z88dk/lib/config

H=$(cd "$(dirname "$0")" && pwd)
TOP=$H/../../..
Z80=$H/../..
OUT=$H/out
mkdir -p "$OUT"

build() {  # kind name flags
        kind=$1; name=$2; flags=$3
        extra=""
        case "$flags" in *UNICODE*) extra="$TOP/unicode.c";; esac
        if [ "$kind" = c ]; then
                src="$TOP/usmb2.c"
                aflags=""
        else
                src="$H/../usmb2.asm"
                aflags=$(for f in $flags; do echo -n " -Ca$f"; done)
        fi
        zcc +test -vn -DZ80 -DAMALLOC $flags $aflags -I"$TOP" -I"$Z80" \
            "$H/test.c" "$src" $extra -o "$OUT/$name.$kind.bin" -lndos -m \
            2> "$OUT/$name.$kind.err" || { cat "$OUT/$name.$kind.err"; return 1; }
        z88dk-ticks -mz80 -counter 2000000000 "$OUT/$name.$kind.bin" | grep -v '^Ticks:' > "$OUT/$name.$kind.out"
}

if [ -n "$1" ]; then
        build "$1" "$2" "$3" && cat "$OUT/$2.$1.out"
        exit $?
fi

rc=0
while read name flags; do
        flags=$(echo $flags | sed 's/\([A-Z_]*\)/-DUSMB2_FEATURE_\1/g')
        build c "$name" "$flags" || { rc=1; continue; }
        build asm "$name" "$flags" || { rc=1; continue; }
        if cmp -s "$OUT/$name.c.out" "$OUT/$name.asm.out"; then
                echo "PASS $name ($(wc -l < "$OUT/$name.c.out") lines, bin c=$(stat -c %s "$OUT/$name.c.bin") asm=$(stat -c %s "$OUT/$name.asm.bin"))"
        else
                echo "FAIL $name"; rc=1
                diff "$OUT/$name.c.out" "$OUT/$name.asm.out" | head -20
        fi
done <<EOF
basic
write WRITE
write_opendir WRITE OPENDIR
write_opendir_unicode WRITE OPENDIR UNICODE
close CLOSE
ntlm NTLM
all WRITE OPENDIR UNICODE CLOSE NTLM
EOF
exit $rc
