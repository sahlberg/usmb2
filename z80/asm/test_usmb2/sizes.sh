#!/bin/sh
# Size table: C (code+rodata+data+bss from z80nm) vs asm
export PATH=/data/sahlberg/z88dk/bin:$PATH ZCCCFG=/data/sahlberg/z88dk/lib/config
H=$(cd "$(dirname "$0")" && pwd); T=$H/out; mkdir -p $T
sz() { z88dk-z80nm -a "$1" | awk '/Section [a-z_]*:/ {gsub(":","",$2); s[$2]=$3} END {c=s["code_compiler"]; r=s["rodata_compiler"]+0; d=s["data_compiler"]+0; b=s["bss_compiler"]+0; printf "%d %d %d %d %d", c, r, d, b, c+r+d+b}'; }
printf "%-24s %-26s %-26s %s\n" config "C code/ro/data/bss=total" "asm code/ro/data/bss=total" "asm/C"
while read name flags; do
  fl=$(echo $flags | sed 's/\([A-Z_]*\)/-DUSMB2_FEATURE_\1/g')
  (cd $H/../.. && zcc +zx -c -o $T/sz_c.o ../usmb2.c -I.. -I. -DZ80 $fl 2>/dev/null)
  z88dk-z80asm $fl -o$T/sz_a.o $H/../usmb2.asm || exit 1
  set -- $(sz $T/sz_c.o); c="$1/$2/$3/$4=$5"; ct=$5
  set -- $(sz $T/sz_a.o); a="$1/$2/$3/$4=$5"; at=$5
  printf "%-24s %-26s %-26s %s\n" "$name" "$c" "$a" $(awk "BEGIN{printf \"%.3f\", $at/$ct}")
done <<X
basic
write WRITE
write_opendir WRITE OPENDIR
write_opendir_unicode WRITE OPENDIR UNICODE
close CLOSE
ntlm NTLM
all WRITE OPENDIR UNICODE CLOSE NTLM
X
