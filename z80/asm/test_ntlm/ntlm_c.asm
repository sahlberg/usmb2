;* * * * *  Small-C/Plus z88dk * * * * *
;  Version: 24219-85e0f836ee-20251229
;
;	Reconstructed for z80 Module Assembler
;
;	Module compile time: Fri Sep 25 17:06:06 2026


	C_LINE	0,"../../../ntlm.c"

	MODULE	X_________ntlm_c


	INCLUDE "z80_crt0.hdr"


	C_LINE	0,"/data/sahlberg/z88dk/lib/config/../..//include/endian.h"
	C_LINE	0,"/data/sahlberg/z88dk/lib/config/../..//include/sys/compiler.h"
	C_LINE	0,"/data/sahlberg/z88dk/lib/config/../..//include/sys/proto.h"
	C_LINE	6,"/data/sahlberg/z88dk/lib/config/../..//include/sys/compiler.h"
	C_LINE	10,"/data/sahlberg/z88dk/lib/config/../..//include/endian.h"
	C_LINE	9,"../../../ntlm.c"
	C_LINE	0,"../../../usmb2.h"
	C_LINE	0,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	0,"/data/sahlberg/z88dk/lib/config/../..//include/sys/types.h"
	C_LINE	17,"/data/sahlberg/z88dk/lib/config/../..//include/sys/types.h"
	C_LINE	26,"/data/sahlberg/z88dk/lib/config/../..//include/sys/types.h"
	C_LINE	38,"/data/sahlberg/z88dk/lib/config/../..//include/sys/types.h"
	C_LINE	44,"/data/sahlberg/z88dk/lib/config/../..//include/sys/types.h"
	C_LINE	49,"/data/sahlberg/z88dk/lib/config/../..//include/sys/types.h"
	C_LINE	54,"/data/sahlberg/z88dk/lib/config/../..//include/sys/types.h"
	C_LINE	59,"/data/sahlberg/z88dk/lib/config/../..//include/sys/types.h"
	C_LINE	64,"/data/sahlberg/z88dk/lib/config/../..//include/sys/types.h"
	C_LINE	69,"/data/sahlberg/z88dk/lib/config/../..//include/sys/types.h"
	C_LINE	74,"/data/sahlberg/z88dk/lib/config/../..//include/sys/types.h"
	C_LINE	79,"/data/sahlberg/z88dk/lib/config/../..//include/sys/types.h"
	C_LINE	84,"/data/sahlberg/z88dk/lib/config/../..//include/sys/types.h"
	C_LINE	89,"/data/sahlberg/z88dk/lib/config/../..//include/sys/types.h"
	C_LINE	93,"/data/sahlberg/z88dk/lib/config/../..//include/sys/types.h"
	C_LINE	94,"/data/sahlberg/z88dk/lib/config/../..//include/sys/types.h"
	C_LINE	95,"/data/sahlberg/z88dk/lib/config/../..//include/sys/types.h"
	C_LINE	97,"/data/sahlberg/z88dk/lib/config/../..//include/sys/types.h"
	C_LINE	98,"/data/sahlberg/z88dk/lib/config/../..//include/sys/types.h"
	C_LINE	99,"/data/sahlberg/z88dk/lib/config/../..//include/sys/types.h"
	C_LINE	105,"/data/sahlberg/z88dk/lib/config/../..//include/sys/types.h"
	C_LINE	110,"/data/sahlberg/z88dk/lib/config/../..//include/sys/types.h"
	C_LINE	11,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	20,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	21,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	22,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	24,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	25,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	26,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	28,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	29,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	30,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	32,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	33,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	34,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	36,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	37,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	38,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	40,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	41,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	42,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	44,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	45,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	47,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	48,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	50,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	51,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	56,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	59,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	61,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	62,"/data/sahlberg/z88dk/lib/config/../..//include/stdint.h"
	C_LINE	5,"../../../usmb2.h"
	C_LINE	30,"../../../usmb2.h"
	C_LINE	40,"../../../usmb2.h"
	C_LINE	45,"../../../usmb2.h"
	C_LINE	55,"../../../usmb2.h"
	C_LINE	57,"../../../usmb2.h"
	C_LINE	58,"../../../usmb2.h"
	C_LINE	59,"../../../usmb2.h"
	C_LINE	60,"../../../usmb2.h"
	C_LINE	62,"../../../usmb2.h"
	C_LINE	63,"../../../usmb2.h"
	C_LINE	19,"../../../ntlm.c"
	C_LINE	0,"../../../ntlm.h"
	C_LINE	9,"../../../ntlm.h"
	C_LINE	20,"../../../ntlm.c"
	C_LINE	0,"../../../md4.h"
	C_LINE	33,"../../../md4.h"
	C_LINE	39,"../../../md4.h"
	C_LINE	40,"../../../md4.h"
	C_LINE	41,"../../../md4.h"
	C_LINE	21,"../../../ntlm.c"
	C_LINE	0,"../../../hmac-md5.h"
	C_LINE	0,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	7,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	9,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	13,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	15,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	19,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	21,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	25,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	27,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	32,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	34,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	38,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	40,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	44,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	46,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	50,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	52,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	57,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	59,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	63,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	65,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	69,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	71,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	76,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	77,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	78,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	81,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	83,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	87,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	89,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	94,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	96,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	101,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	103,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	108,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	110,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	115,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	117,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	122,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	124,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	128,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	130,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	138,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	140,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	144,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	146,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	150,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	152,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	157,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	159,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	163,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	165,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	169,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	171,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	175,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	177,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	181,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	183,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	187,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	189,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	193,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	195,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	199,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	201,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	205,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	207,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	212,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	214,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	219,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	221,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	226,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	228,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	232,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	234,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	238,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	240,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	245,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	247,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	253,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	255,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	259,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	261,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	265,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	267,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	271,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	273,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	278,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	280,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	284,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	286,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	290,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	292,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	296,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	298,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	302,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	304,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	308,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	310,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	314,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	316,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	320,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	321,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	323,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	328,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	330,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	335,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	336,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	338,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	343,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	345,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	349,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	351,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	355,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	357,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	361,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	363,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	369,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	371,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	375,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	377,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	381,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	383,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	387,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	389,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	394,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	396,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	400,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	401,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	403,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	409,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	411,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	415,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	417,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	425,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	425,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	427,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	429,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	430,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	431,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	433,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	434,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	436,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	437,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	439,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	440,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	442,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	443,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	444,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	446,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	447,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	448,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	449,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	464,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	470,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	476,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	482,"/data/sahlberg/z88dk/lib/config/../..//include/string.h"
	C_LINE	13,"../../../hmac-md5.h"
	C_LINE	0,"../../../md5.h"
	C_LINE	0,"/data/sahlberg/z88dk/lib/config/../..//include/stddef.h"
	C_LINE	12,"/data/sahlberg/z88dk/lib/config/../..//include/stddef.h"
	C_LINE	17,"/data/sahlberg/z88dk/lib/config/../..//include/stddef.h"
	C_LINE	8,"../../../md5.h"
	C_LINE	14,"../../../md5.h"
	C_LINE	20,"../../../md5.h"
	C_LINE	21,"../../../md5.h"
	C_LINE	22,"../../../md5.h"
	C_LINE	23,"../../../md5.h"
	C_LINE	20,"../../../hmac-md5.h"
	C_LINE	27,"../../../hmac-md5.h"
	C_LINE	30,"../../../hmac-md5.h"
	C_LINE	22,"../../../ntlm.c"
	C_LINE	0,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	0,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	0,"/data/sahlberg/z88dk/lib/config/../..//include/rect.h"
	C_LINE	21,"/data/sahlberg/z88dk/lib/config/../..//include/rect.h"
	C_LINE	28,"/data/sahlberg/z88dk/lib/config/../..//include/rect.h"
	C_LINE	35,"/data/sahlberg/z88dk/lib/config/../..//include/rect.h"
	C_LINE	44,"/data/sahlberg/z88dk/lib/config/../..//include/rect.h"
	C_LINE	55,"/data/sahlberg/z88dk/lib/config/../..//include/rect.h"
	C_LINE	56,"/data/sahlberg/z88dk/lib/config/../..//include/rect.h"
	C_LINE	57,"/data/sahlberg/z88dk/lib/config/../..//include/rect.h"
	C_LINE	58,"/data/sahlberg/z88dk/lib/config/../..//include/rect.h"
	C_LINE	60,"/data/sahlberg/z88dk/lib/config/../..//include/rect.h"
	C_LINE	61,"/data/sahlberg/z88dk/lib/config/../..//include/rect.h"
	C_LINE	62,"/data/sahlberg/z88dk/lib/config/../..//include/rect.h"
	C_LINE	63,"/data/sahlberg/z88dk/lib/config/../..//include/rect.h"
	C_LINE	67,"/data/sahlberg/z88dk/lib/config/../..//include/rect.h"
	C_LINE	68,"/data/sahlberg/z88dk/lib/config/../..//include/rect.h"
	C_LINE	70,"/data/sahlberg/z88dk/lib/config/../..//include/rect.h"
	C_LINE	71,"/data/sahlberg/z88dk/lib/config/../..//include/rect.h"
	C_LINE	18,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	0,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/zx_input.h"
	C_LINE	64,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/zx_input.h"
	C_LINE	65,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/zx_input.h"
	C_LINE	66,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/zx_input.h"
	C_LINE	67,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/zx_input.h"
	C_LINE	68,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/zx_input.h"
	C_LINE	69,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/zx_input.h"
	C_LINE	76,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/zx_input.h"
	C_LINE	77,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/zx_input.h"
	C_LINE	78,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/zx_input.h"
	C_LINE	80,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/zx_input.h"
	C_LINE	81,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/zx_input.h"
	C_LINE	82,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/zx_input.h"
	C_LINE	93,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/zx_input.h"
	C_LINE	94,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/zx_input.h"
	C_LINE	95,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/zx_input.h"
	C_LINE	97,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/zx_input.h"
	C_LINE	98,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/zx_input.h"
	C_LINE	19,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	158,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	159,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	160,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	161,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	162,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	163,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	164,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	165,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	166,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	167,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	168,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	169,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	170,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	171,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	172,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	173,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	174,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	175,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	176,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	177,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	178,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	179,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	186,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	187,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	188,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	189,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	190,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	198,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	202,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	205,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	208,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	209,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	212,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	213,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	216,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	217,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	219,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	220,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	221,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	222,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	344,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	345,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	347,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	349,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	396,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	399,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	402,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	408,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	416,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	417,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	418,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	420,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	421,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	447,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	453,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	454,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	463,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	464,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	473,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	474,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	483,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	484,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	490,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	491,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	499,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	500,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	506,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	507,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	512,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	513,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	518,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	519,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	521,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	522,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	537,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	540,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	541,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	545,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	546,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	550,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	551,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	556,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	557,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	561,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	562,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	566,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	567,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	571,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	572,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	576,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	577,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	581,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	582,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	612,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	613,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	616,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	618,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	619,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	621,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	622,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	624,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	625,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	627,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	629,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	630,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	631,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	632,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	634,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	635,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	636,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	637,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	639,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	640,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	641,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	642,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	643,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	655,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	656,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	658,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	659,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	661,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	662,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	664,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	665,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	667,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	669,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	670,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	671,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	672,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	674,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	675,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	683,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	684,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	0,"/data/sahlberg/z88dk/lib/config/../..//include/interrupt.h"
	C_LINE	6,"/data/sahlberg/z88dk/lib/config/../..//include/interrupt.h"
	C_LINE	19,"/data/sahlberg/z88dk/lib/config/../..//include/interrupt.h"
	C_LINE	21,"/data/sahlberg/z88dk/lib/config/../..//include/interrupt.h"
	C_LINE	23,"/data/sahlberg/z88dk/lib/config/../..//include/interrupt.h"
	C_LINE	26,"/data/sahlberg/z88dk/lib/config/../..//include/interrupt.h"
	C_LINE	28,"/data/sahlberg/z88dk/lib/config/../..//include/interrupt.h"
	C_LINE	30,"/data/sahlberg/z88dk/lib/config/../..//include/interrupt.h"
	C_LINE	33,"/data/sahlberg/z88dk/lib/config/../..//include/interrupt.h"
	C_LINE	37,"/data/sahlberg/z88dk/lib/config/../..//include/interrupt.h"
	C_LINE	38,"/data/sahlberg/z88dk/lib/config/../..//include/interrupt.h"
	C_LINE	690,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	694,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	700,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	701,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	703,"/data/sahlberg/z88dk/lib/config/../..//include/arch/zx/spectrum.h"
	C_LINE	13,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	0,"/data/sahlberg/z88dk/lib/config/../..//include/fcntl.h"
	C_LINE	34,"/data/sahlberg/z88dk/lib/config/../..//include/fcntl.h"
	C_LINE	36,"/data/sahlberg/z88dk/lib/config/../..//include/fcntl.h"
	C_LINE	37,"/data/sahlberg/z88dk/lib/config/../..//include/fcntl.h"
	C_LINE	39,"/data/sahlberg/z88dk/lib/config/../..//include/fcntl.h"
	C_LINE	41,"/data/sahlberg/z88dk/lib/config/../..//include/fcntl.h"
	C_LINE	42,"/data/sahlberg/z88dk/lib/config/../..//include/fcntl.h"
	C_LINE	45,"/data/sahlberg/z88dk/lib/config/../..//include/fcntl.h"
	C_LINE	50,"/data/sahlberg/z88dk/lib/config/../..//include/fcntl.h"
	C_LINE	51,"/data/sahlberg/z88dk/lib/config/../..//include/fcntl.h"
	C_LINE	53,"/data/sahlberg/z88dk/lib/config/../..//include/fcntl.h"
	C_LINE	59,"/data/sahlberg/z88dk/lib/config/../..//include/fcntl.h"
	C_LINE	60,"/data/sahlberg/z88dk/lib/config/../..//include/fcntl.h"
	C_LINE	61,"/data/sahlberg/z88dk/lib/config/../..//include/fcntl.h"
	C_LINE	64,"/data/sahlberg/z88dk/lib/config/../..//include/fcntl.h"
	C_LINE	83,"/data/sahlberg/z88dk/lib/config/../..//include/fcntl.h"
	C_LINE	92,"/data/sahlberg/z88dk/lib/config/../..//include/fcntl.h"
	C_LINE	105,"/data/sahlberg/z88dk/lib/config/../..//include/fcntl.h"
	C_LINE	106,"/data/sahlberg/z88dk/lib/config/../..//include/fcntl.h"
	C_LINE	108,"/data/sahlberg/z88dk/lib/config/../..//include/fcntl.h"
	C_LINE	110,"/data/sahlberg/z88dk/lib/config/../..//include/fcntl.h"
	C_LINE	83,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	96,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	146,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	165,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	170,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	171,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	203,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	206,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	210,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	211,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	212,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	214,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	215,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	219,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	224,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	225,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	227,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	234,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	236,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	238,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	244,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	246,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	256,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	259,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	261,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	263,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	268,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	270,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	274,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	283,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	284,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	288,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	297,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	298,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	301,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	303,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	304,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	305,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	306,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	307,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	308,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	316,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	317,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	318,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	324,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	331,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	332,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	333,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	334,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	335,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	345,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	350,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	355,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	358,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	361,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	364,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	366,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	369,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	371,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	372,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	374,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	376,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	380,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	382,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	386,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	389,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	398,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	400,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	403,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	405,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	407,"/data/sahlberg/z88dk/lib/config/../..//include/stdio.h"
	C_LINE	24,"../../../ntlm.c"
	C_LINE	44,"../../../ntlm.c"
	SECTION	code_compiler

; Function ntlm_generate_auth flags 0x00000200 __smallc 
; int ntlm_generate_auth(struct usmb2_context * usmb2, char * username, char * password)
; parameter 'char * password' at sp+2 size(2)
; parameter 'char * username' at sp+4 size(2)
; parameter 'struct usmb2_context * usmb2' at sp+6 size(2)
	C_LINE	47,"../../../ntlm.c::ntlm_generate_auth::0::0"
._ntlm_generate_auth
	ld	hl,65520	;const
	add	hl,sp
	ld	sp,hl
	dec	sp
	pop	hl
	ld	l,0
	push	hl
	ld	hl,65510	;const
	add	hl,sp
	ld	sp,hl
	ld	hl,24	;const
	add	hl,sp
	push	hl
	ld	hl,51	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,90
	add	hl,bc
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,-64
	add	hl,bc
	pop	de
	call	l_pint
	ld	hl,22	;const
	add	hl,sp
	ld	(hl),92
	inc	hl
	ld	(hl),0
	ld	hl,20	;const
	add	hl,sp
	push	hl
	ld	hl,26	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,12
	add	hl,bc
	pop	de
	call	l_pint
	ld	hl,16	;const
	add	hl,sp
	push	hl
	ld	hl,51	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	ex	de,hl
	ld	hl,22	;const
	add	hl,sp
	call	l_gint	;
	add	hl,de
	call	l_gint	;
	pop	de
	call	l_pint
	ld	hl,14	;const
	add	hl,sp
	push	hl
	ld	hl,51	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,28	;const
	call	l_gintspsp	;
	ld	hl,55	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,28	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,4
	add	hl,bc
	pop	de
	add	hl,de
	call	l_glong
	exx
	pop	hl
	ld	de,0
	push	de
	push	hl
	exx
	call	l_long_add
	pop	de
	add	hl,de
	pop	de
	call	l_pint
	ld	hl,18	;const
	add	hl,sp
	ld	(hl),72
	inc	hl
	ld	(hl),0
	ld	hl,10	;const
	add	hl,sp
	push	hl
	ld	hl,49	;const
	add	hl,sp
	call	l_gint	;
	call	strlen_fastcall
	add	hl,hl
	pop	de
	call	l_pint
	ld	hl,12	;const
	add	hl,sp
	push	hl
	ld	hl,18	;const
	add	hl,sp
	ld	e,(hl)
	inc	hl
	ld	d,(hl)
	ld	hl,20	;const
	add	hl,sp
	call	l_gint	;
	add	hl,de
	pop	de
	call	l_pint
	ld	hl,8	;const
	add	hl,sp
	push	hl
	ld	hl,12	;const
	add	hl,sp
	ld	e,(hl)
	inc	hl
	ld	d,(hl)
	ld	hl,14	;const
	add	hl,sp
	call	l_gint	;
	add	hl,de
	pop	de
	call	l_pint
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,10	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,100
	add	hl,bc
	pop	de
	add	hl,de
	push	hl
	ld	hl,51	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,28	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,24
	add	hl,bc
	pop	de
	add	hl,de
	pop	de
	ld	bc,8
	ldir
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,26	;const
	call	l_gintspsp	;
	ld	hl,53	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,30	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,44
	add	hl,bc
	pop	de
	add	hl,de
	call	l_glong
	exx
	pop	hl
	ld	de,0
	push	de
	push	hl
	exx
	call	l_long_add
	pop	de
	add	hl,de
	pop	bc
	push	hl
	ld	hl,26	;const
	add	hl,sp
	ld	(hl),0
.i_2
	ld	hl,6	;const
	add	hl,sp
	push	hl
	ld	hl,2	;const
	call	l_gintspsp	;
	ld	hl,30	;const
	add	hl,sp
	call	l_gchar
	pop	de
	add	hl,de
	call	l_gint	;
	pop	de
	call	l_pint
	ld	hl,4	;const
	add	hl,sp
	push	hl
	ld	hl,2	;const
	call	l_gintspsp	;
	ld	hl,30	;const
	add	hl,sp
	call	l_gchar
	inc	hl
	inc	hl
	pop	de
	add	hl,de
	call	l_gint	;
	pop	de
	call	l_pint
	call	l_gint6sp	;
	ld	a,h
	or	l
	jp	z,i_3	;EOS
.i_4
	ld	hl,26	;const
	add	hl,sp
	push	hl
	call	l_gchar
	push	hl
	call	l_gint8sp	;
	ld	bc,4
	add	hl,bc
	pop	de
	add	hl,de
	ld	a,l
	pop	de
	ld	(de),a
	jp	i_2	;EOS
.i_3
	ld	hl,20	;const
	add	hl,sp
	push	hl
	ld	hl,10	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,136
	add	hl,bc
	pop	de
	call	l_pint
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	ex	de,hl
	ld	hl,20	;const
	add	hl,sp
	call	l_gint	;
	add	hl,de
	push	hl
	ld	hl,2	;const
	call	l_gintspsp	;
	ld	hl,30	;const
	add	hl,sp
	call	l_gchar
	push	hl
	call	memcpy_callee
	ld	hl,20	;const
	add	hl,sp
	push	hl
	ld	e,(hl)
	inc	hl
	ld	d,(hl)
	push	de
	ld	hl,30	;const
	add	hl,sp
	call	l_gchar
	pop	de
	add	hl,de
	pop	de
	call	l_pint
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	ex	de,hl
	ld	hl,20	;const
	add	hl,sp
	call	l_gint	;
	add	hl,de
	ld	(hl),9
	inc	hl
	ld	(hl),0
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,22	;const
	add	hl,sp
	call	l_gint	;
	inc	hl
	inc	hl
	pop	de
	add	hl,de
	push	hl
	ld	hl,18	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,10
	add	hl,bc
	pop	de
	call	l_pint
	ld	hl,20	;const
	add	hl,sp
	push	hl
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,4
	add	hl,bc
	pop	de
	call	l_pint
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	ex	de,hl
	ld	hl,20	;const
	add	hl,sp
	call	l_gint	;
	add	hl,de
	ld	(hl),99
	inc	hl
	ld	(hl),0
	ld	hl,20	;const
	add	hl,sp
	push	hl
	call	l_gint	;
	inc	hl
	inc	hl
	pop	de
	call	l_pint
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	ex	de,hl
	ld	hl,20	;const
	add	hl,sp
	call	l_gint	;
	add	hl,de
	ld	(hl),105
	inc	hl
	ld	(hl),0
	ld	hl,20	;const
	add	hl,sp
	push	hl
	call	l_gint	;
	inc	hl
	inc	hl
	pop	de
	call	l_pint
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	ex	de,hl
	ld	hl,20	;const
	add	hl,sp
	call	l_gint	;
	add	hl,de
	ld	(hl),102
	inc	hl
	ld	(hl),0
	ld	hl,20	;const
	add	hl,sp
	push	hl
	call	l_gint	;
	inc	hl
	inc	hl
	pop	de
	call	l_pint
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	ex	de,hl
	ld	hl,20	;const
	add	hl,sp
	call	l_gint	;
	add	hl,de
	ld	(hl),115
	inc	hl
	ld	(hl),0
	ld	hl,20	;const
	add	hl,sp
	push	hl
	call	l_gint	;
	inc	hl
	inc	hl
	pop	de
	call	l_pint
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	ex	de,hl
	ld	hl,20	;const
	add	hl,sp
	call	l_gint	;
	add	hl,de
	ld	(hl),47
	inc	hl
	ld	(hl),0
	ld	hl,20	;const
	add	hl,sp
	push	hl
	call	l_gint	;
	inc	hl
	inc	hl
	pop	de
	call	l_pint
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	ex	de,hl
	ld	hl,20	;const
	add	hl,sp
	call	l_gint	;
	add	hl,de
	push	hl
	ld	hl,16	;const
	call	l_gintspsp	;
	ld	hl,20	;const
	add	hl,sp
	call	l_gint	;
	push	hl
	call	memcpy_callee
	ld	hl,20	;const
	add	hl,sp
	push	hl
	ld	e,(hl)
	inc	hl
	ld	d,(hl)
	ld	hl,18	;const
	add	hl,sp
	call	l_gint
	add	hl,de
	pop	de
	call	l_pint
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	ex	de,hl
	ld	hl,20	;const
	add	hl,sp
	call	l_gint	;
	add	hl,de
	push	hl
	ld	e,0
	ld	b,8
.i_5
	ld	(hl),e
	inc	hl
	djnz	i_5
	pop	hl
	ld	hl,20	;const
	add	hl,sp
	push	hl
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,8
	add	hl,bc
	pop	de
	call	l_pint
	ld	hl,20	;const
	add	hl,sp
	call	l_gint	;
	pop	de
	pop	bc
	push	hl
	push	de
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,20	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,92
	add	hl,bc
	pop	de
	add	hl,de
	push	hl
	ld	hl,16	;const
	call	l_gintspsp	;
	ld	hl,20	;const
	add	hl,sp
	call	l_gint	;
	push	hl
	call	memcpy_callee
	ld	hl,14	;const
	add	hl,sp
	push	hl
	ld	hl,51	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,22	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,92
	add	hl,bc
	pop	de
	add	hl,de
	pop	de
	call	l_pint
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,24	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,28
	add	hl,bc
	pop	de
	add	hl,de
	ex	de,hl
	ld	hl,16	;const
	add	hl,sp
	ldi
	ldi
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,24	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,30
	add	hl,bc
	pop	de
	add	hl,de
	ex	de,hl
	ld	hl,16	;const
	add	hl,sp
	ldi
	ldi
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,24	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,32
	add	hl,bc
	pop	de
	add	hl,de
	push	hl
	ld	hl,20	;const
	add	hl,sp
	call	l_gint	;
	ld	de,0
	pop	bc
	call	l_plong
	ld	hl,6	;const
	add	hl,sp
	push	hl
	call	l_gint4sp	;
	ld	bc,-92
	add	hl,bc
	ex	de,hl
	ld	hl,10	;const
	add	hl,sp
	call	l_gint	;
	ex	de,hl
	and	a
	sbc	hl,de
	pop	de
	call	l_pint
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,24	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,20
	add	hl,bc
	pop	de
	add	hl,de
	ex	de,hl
	call	l_gint6sp
	call	l_pint
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,24	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,22
	add	hl,bc
	pop	de
	add	hl,de
	ex	de,hl
	call	l_gint6sp
	call	l_pint
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,24	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,24
	add	hl,bc
	pop	de
	add	hl,de
	push	hl
	ld	hl,10	;const
	add	hl,sp
	call	l_gint	;
	ld	de,0
	pop	bc
	call	l_plong
	ld	hl,6	;const
	add	hl,sp
	xor	a
	ld	(hl),a
	inc	hl
	ld	(hl),a
.i_6
	ld	hl,10	;const
	add	hl,sp
	ld	e,(hl)
	inc	hl
	ld	d,(hl)
	ld	hl,6	;const
	add	hl,sp
	ld	a,(hl)
	inc	hl
	ld	h,(hl)
	ld	l,a
	and	a
	sbc	hl,de
	jp	nc,i_7	;
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,14	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,92
	add	hl,bc
	push	hl
	ld	hl,10	;const
	add	hl,sp
	inc	(hl)
	ld	a,(hl)
	inc	hl
	jr	nz,ASMPC+3
	inc	(hl)
	ld	h,(hl)
	ld	l,a
	dec	hl
	pop	de
	add	hl,de
	pop	de
	add	hl,de
	push	hl
	ld	hl,49	;const
	call	l_gintspsp	;
	ld	hl,10	;const
	add	hl,sp
	call	l_gint	;
	srl	h
	rr	l
	pop	de
	add	hl,de
	pop	de
	ld	a,(hl)
	ld	(de),a
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,14	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,92
	add	hl,bc
	push	hl
	ld	hl,10	;const
	add	hl,sp
	inc	(hl)
	ld	a,(hl)
	inc	hl
	jr	nz,ASMPC+3
	inc	(hl)
	ld	h,(hl)
	ld	l,a
	dec	hl
	pop	de
	add	hl,de
	pop	de
	add	hl,de
	ld	(hl),0
	jp	i_6	;EOS
.i_7
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,24	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,36
	add	hl,bc
	pop	de
	add	hl,de
	ex	de,hl
	ld	hl,10	;const
	add	hl,sp
	ldi
	ldi
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,24	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,38
	add	hl,bc
	pop	de
	add	hl,de
	ex	de,hl
	ld	hl,10	;const
	add	hl,sp
	ldi
	ldi
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,24	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,40
	add	hl,bc
	pop	de
	add	hl,de
	push	hl
	ld	hl,14	;const
	add	hl,sp
	call	l_gint	;
	ld	de,0
	pop	bc
	call	l_plong
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,24	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,44
	add	hl,bc
	pop	de
	add	hl,de
	push	hl
	ld	e,0
	ld	b,12
.i_9
	ld	(hl),e
	inc	hl
	djnz	i_9
	pop	hl
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,24	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,56
	add	hl,bc
	pop	de
	add	hl,de
	ld	(hl),55
	inc	hl
	ld	(hl),128
	inc	hl
	ld	(hl),8
	inc	hl
	ld	(hl),32
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,24	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,60
	add	hl,bc
	pop	de
	add	hl,de
	push	hl
	ld	e,0
	ld	b,8
.i_10
	ld	(hl),e
	inc	hl
	djnz	i_10
	pop	hl
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	call	_MD4Init
	pop	bc
	ld	hl,26	;const
	add	hl,sp
	ld	(hl),0
.i_11
	ld	hl,45	;const
	add	hl,sp
	call	l_gint	;
	ld	a,(hl)
	and	a
	jp	z,i_12	;
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,47	;const
	add	hl,sp
	inc	(hl)
	ld	a,(hl)
	inc	hl
	jr	nz,ASMPC+3
	inc	(hl)
	ld	h,(hl)
	ld	l,a
	dec	hl
	push	hl
	ld	hl,1	;const
	push	hl
	call	_MD4Update
	pop	bc
	pop	bc
	pop	bc
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,28	;const
	add	hl,sp
	push	hl
	ld	hl,1	;const
	push	hl
	call	_MD4Update
	pop	bc
	pop	bc
	pop	bc
	jp	i_11	;EOS
.i_12
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,182
	add	hl,bc
	push	hl
	ld	hl,51	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	call	_MD4Final
	pop	bc
	pop	bc
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,49	;const
	call	l_gintspsp	;
	ld	hl,0	;const
	push	hl
	push	hl
	ld	hl,22	;const
	call	l_gintspsp	;
	ld	hl,26	;const
	call	l_gintspsp	;
	ld	hl,61	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,182
	add	hl,bc
	push	hl
	ld	hl,16	;const
	push	hl
	ld	l,43
	add	hl,sp
	push	hl
	call	_hmac_md5
	ld	hl,18	;const
	add	hl,sp
	ld	sp,hl
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,10	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,108
	add	hl,bc
	pop	de
	add	hl,de
	push	hl
	ld	e,0
	ld	b,28
.i_13
	ld	(hl),e
	inc	hl
	djnz	i_13
	pop	hl
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,10	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,108
	add	hl,bc
	pop	de
	add	hl,de
	ld	(hl),1
	inc	hl
	ld	(hl),1
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,10	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,124
	add	hl,bc
	pop	de
	add	hl,de
	push	hl
	ld	e,1
	ld	b,8
.i_14
	ld	(hl),e
	inc	hl
	djnz	i_14
	pop	hl
	ld	hl,6	;const
	add	hl,sp
	push	hl
	ld	hl,10	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,92
	add	hl,bc
	pop	de
	call	l_pint
	ld	hl,4	;const
	add	hl,sp
	push	hl
	dec	hl
	dec	hl
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,-92
	add	hl,bc
	ex	de,hl
	ld	hl,10	;const
	add	hl,sp
	call	l_gint	;
	ex	de,hl
	and	a
	sbc	hl,de
	pop	de
	call	l_pint
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,0	;const
	push	hl
	ld	l,53
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,12	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,8
	add	hl,bc
	pop	de
	add	hl,de
	push	hl
	ld	hl,10	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,-8
	add	hl,bc
	push	hl
	ld	hl,0	;const
	push	hl
	push	hl
	ld	hl,39	;const
	add	hl,sp
	push	hl
	ld	hl,16	;const
	push	hl
	ld	l,65
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,86
	add	hl,bc
	push	hl
	ld	hl,26	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,92
	add	hl,bc
	pop	de
	add	hl,de
	push	hl
	call	_hmac_md5
	ld	hl,18	;const
	add	hl,sp
	ld	sp,hl
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,186
	add	hl,bc
	push	hl
	ld	e,0
	ld	b,12
.i_15
	ld	(hl),e
	inc	hl
	djnz	i_15
	pop	hl
	ld	hl,49	;const
	add	hl,sp
	ld	c,(hl)
	inc	hl
	ld	b,(hl)
	ld	hl,186
	add	hl,bc
	ld	(hl),3
	pop	bc
	pop	hl
	push	hl
	push	bc
	ld	bc,-92
	add	hl,bc
	exx
	ld	hl,43	;const
	add	hl,sp
	ld	sp,hl
	exx
	ret


	SECTION	bss_compiler
	SECTION	code_compiler
; --- Start of Optimiser additions ---
	defc	i_8 = i_6


; --- Start of Static Variables ---

	SECTION	bss_compiler
	SECTION	code_compiler


; --- Start of Scope Defns ---

	GLOBAL	_usmb2_init_context
	GLOBAL	_usmb2_treeconnect
	GLOBAL	_usmb2_open
	GLOBAL	_usmb2_prw
	GLOBAL	_usmb2_pread
	GLOBAL	_usmb2_pwrite
	GLOBAL	_usmb2_size
	GLOBAL	_usmb2_opendir
	GLOBAL	_usmb2_readdir
	GLOBAL	_ntlm_generate_auth
	GLOBAL	_MD4Init
	GLOBAL	_MD4Update
	GLOBAL	_MD4Final
	GLOBAL	bcmp
	GLOBAL	bcmp_callee
	GLOBAL	bcopy
	GLOBAL	bcopy_callee
	GLOBAL	bzero
	GLOBAL	bzero_callee
	GLOBAL	index
	GLOBAL	index_callee
	GLOBAL	rindex
	GLOBAL	rindex_callee
	GLOBAL	strset
	GLOBAL	strset_callee
	GLOBAL	strnset
	GLOBAL	strnset_callee
	GLOBAL	rawmemchr
	GLOBAL	rawmemchr_callee
	GLOBAL	_memlwr_
	GLOBAL	_memlwr__callee
	GLOBAL	_memstrcpy_
	GLOBAL	_memstrcpy__callee
	GLOBAL	_memupr_
	GLOBAL	_memupr__callee
	GLOBAL	_strrstrip_
	GLOBAL	ffs
	GLOBAL	ffsl
	GLOBAL	memccpy
	GLOBAL	memccpy_callee
	GLOBAL	memchr
	GLOBAL	memchr_callee
	GLOBAL	memcmp
	GLOBAL	memcmp_callee
	GLOBAL	memcpy
	GLOBAL	memcpy_callee
	GLOBAL	memmem
	GLOBAL	memmem_callee
	GLOBAL	memmove
	GLOBAL	memmove_callee
	GLOBAL	memrchr
	GLOBAL	memrchr_callee
	GLOBAL	memset
	GLOBAL	memset_callee
	GLOBAL	memset_wr
	GLOBAL	memset_wr_callee
	GLOBAL	memswap
	GLOBAL	memswap_callee
	GLOBAL	stpcpy
	GLOBAL	stpcpy_callee
	GLOBAL	stpncpy
	GLOBAL	stpncpy_callee
	GLOBAL	strcasecmp
	GLOBAL	strcasecmp_callee
	GLOBAL	strcat
	GLOBAL	strcat_callee
	GLOBAL	strchr
	GLOBAL	strchr_callee
	GLOBAL	strchrnul
	GLOBAL	strchrnul_callee
	GLOBAL	strcmp
	GLOBAL	strcmp_callee
	GLOBAL	strcoll
	GLOBAL	strcoll_callee
	GLOBAL	strcpy
	GLOBAL	strcpy_callee
	GLOBAL	strcspn
	GLOBAL	strcspn_callee
	GLOBAL	strdup
	GLOBAL	strdup_fastcall
	GLOBAL	strerror
	GLOBAL	strerror_fastcall
	GLOBAL	stricmp
	GLOBAL	stricmp_callee
	GLOBAL	strlcat
	GLOBAL	strlcat_callee
	GLOBAL	strlcpy
	GLOBAL	strlcpy_callee
	GLOBAL	strlen
	GLOBAL	strlen_fastcall
	GLOBAL	strlwr
	GLOBAL	strlwr_fastcall
	GLOBAL	strncasecmp
	GLOBAL	strncasecmp_callee
	GLOBAL	strncat
	GLOBAL	strncat_callee
	GLOBAL	strnchar
	GLOBAL	strnchr_callee
	GLOBAL	strncmp
	GLOBAL	strncmp_callee
	GLOBAL	strncpy
	GLOBAL	strncpy_callee
	GLOBAL	strndup
	GLOBAL	strndup_callee
	GLOBAL	strnicmp
	GLOBAL	strnicmp_callee
	GLOBAL	strnlen
	GLOBAL	strnlen_callee
	GLOBAL	strpkbrk
	GLOBAL	strpbrk_callee
	GLOBAL	strrchr
	GLOBAL	strrchr_callee
	GLOBAL	strrcspn
	GLOBAL	strrcspn_callee
	GLOBAL	strrev
	GLOBAL	strrev_fastcall
	GLOBAL	strrspn
	GLOBAL	strrspn_callee
	GLOBAL	strrstrip
	GLOBAL	strrstrip_fastcall
	GLOBAL	strsep
	GLOBAL	strsep_callee
	GLOBAL	strspn
	GLOBAL	strspn_callee
	GLOBAL	strstr
	GLOBAL	strstr_callee
	GLOBAL	strstrip
	GLOBAL	strstrip_fastcall
	GLOBAL	strtok
	GLOBAL	strtok_callee
	GLOBAL	strtok_r
	GLOBAL	strtok_r_callee
	GLOBAL	strupr
	GLOBAL	strupr_fastcall
	GLOBAL	strxfrm
	GLOBAL	strxfrm_callee
	GLOBAL	strrstr
	GLOBAL	strrstr_callee
	GLOBAL	memopi
	GLOBAL	memopi_callee
	GLOBAL	memopd
	GLOBAL	memopd_callee
	GLOBAL	strdupf
	GLOBAL	strlenf
	GLOBAL	strcasecmpf
	GLOBAL	strcmpf
	GLOBAL	strncmpf
	GLOBAL	strcpyf
	GLOBAL	strncpyf
	GLOBAL	strcatf
	GLOBAL	strncatf
	GLOBAL	strlwrf
	GLOBAL	struprf
	GLOBAL	strchrf
	GLOBAL	strnchrf
	GLOBAL	strrchrf
	GLOBAL	memcpyf
	GLOBAL	memsetf
	GLOBAL	memchrf
	GLOBAL	memcmpf
	GLOBAL	__builtin_memset
	GLOBAL	__builtin_memcpy
	GLOBAL	__builtin_strcpy
	GLOBAL	__builtin_strchr
	GLOBAL	_md5Init
	GLOBAL	_md5Update
	GLOBAL	_md5Finalize
	GLOBAL	_md5Step
	GLOBAL	_hmac_md5
	GLOBAL	r_IsPtInIval8
	GLOBAL	r_IsPtInRect8
	GLOBAL	r_IsIvalInIval8
	GLOBAL	r_IsRectInRect8
	GLOBAL	r_IsPtInIval16
	GLOBAL	r_IsPtInRect16
	GLOBAL	r_IsIvalInIval16
	GLOBAL	r_IsRectInRect16
	GLOBAL	r_IntersectIval8
	GLOBAL	r_IntersectRect8
	GLOBAL	r_IntersectIval16
	GLOBAL	r_IntersectRect16
	GLOBAL	in_JoyFuller
	GLOBAL	in_JoyKempston
	GLOBAL	in_JoySinclair1
	GLOBAL	in_JoySinclair2
	GLOBAL	in_JoyTimex1
	GLOBAL	in_JoyTimex2
	GLOBAL	in_MouseAMXInit
	GLOBAL	in_MouseAMX
	GLOBAL	in_MouseAMXSetPos
	GLOBAL	in_MouseAMXInit_callee
	GLOBAL	in_MouseAMX_callee
	GLOBAL	in_MouseAMXSetPos_callee
	GLOBAL	in_MouseKempInit
	GLOBAL	in_MouseKemp
	GLOBAL	in_MouseKempSetPos
	GLOBAL	in_MouseKemp_callee
	GLOBAL	in_MouseKempSetPos_callee
	GLOBAL	zx_128mode
	GLOBAL	zx_floatingbus
	GLOBAL	zx_issue3
	GLOBAL	zx_type
	GLOBAL	zx_model
	GLOBAL	zx_basic_length
	GLOBAL	zx_var_length
	GLOBAL	zx_printer
	GLOBAL	zx_soundchip
	GLOBAL	zx_fullerstick
	GLOBAL	zx_kempstonmouse
	GLOBAL	zx_kempston
	GLOBAL	zx_iss_stick
	GLOBAL	zx_mb02
	GLOBAL	zx_multiface
	GLOBAL	zx_disciple
	GLOBAL	zx_plus3fdc
	GLOBAL	zx_zxmmc
	GLOBAL	zx_extsys
	GLOBAL	zx_basemem
	GLOBAL	zx_break
	GLOBAL	zx_ulaplus
	GLOBAL	ula_plus_mode
	GLOBAL	ula_normal_mode
	GLOBAL	ula_sync
	GLOBAL	ulaplus_set
	GLOBAL	ulaplus_get
	GLOBAL	zx_syntax
	GLOBAL	zx_goto
	GLOBAL	zx_line
	GLOBAL	zx_getstr
	GLOBAL	zx_setstr
	GLOBAL	zx_getint
	GLOBAL	zx_setint
	GLOBAL	zx_getfloat
	GLOBAL	zx_setfloat
	GLOBAL	zx_getstr_callee
	GLOBAL	zx_setstr_callee
	GLOBAL	zx_setint_callee
	GLOBAL	zx_setfloat_callee
	GLOBAL	zx_lprintc
	GLOBAL	zx_hardcopy
	GLOBAL	zx_print_buf
	GLOBAL	zx_print_row
	GLOBAL	centronics_init
	GLOBAL	_centronics_strobe_delay
	GLOBAL	centronics_send
	GLOBAL	tape_save
	GLOBAL	tape_save_block
	GLOBAL	tape_load_block
	GLOBAL	tape_save_block_callee
	GLOBAL	tape_load_block_callee
	GLOBAL	zx_cls
	GLOBAL	zx_cls_attr
	GLOBAL	zx_cls_attr_fastcall
	GLOBAL	_zx_setattrflash
	GLOBAL	_zx_setattrflash_fastcall
	GLOBAL	_zx_setattrbright
	GLOBAL	_zx_setattrbright_fastcall
	GLOBAL	_zx_setattrinverse
	GLOBAL	_zx_setattrinverse_fastcall
	GLOBAL	zx_border
	GLOBAL	zx_border_fastcall
	GLOBAL	zx_colour
	GLOBAL	zx_colour_fastcall
	GLOBAL	_zx_setink
	GLOBAL	zx_setink_fastcall
	GLOBAL	_zx_setpaper
	GLOBAL	zx_setpaper_fastcall
	GLOBAL	zx_attr
	GLOBAL	zx_screenstr
	GLOBAL	zx_attr_callee
	GLOBAL	zx_screenstr_callee
	GLOBAL	zx_printf
	GLOBAL	zx_scroll_up
	GLOBAL	zx_scroll_up_callee
	GLOBAL	zx_scroll_up_attr
	GLOBAL	zx_scroll_up_attr_callee
	GLOBAL	zx_scroll_up_pix
	GLOBAL	zx_scroll_up_pix_callee
	GLOBAL	zx_cls_wc
	GLOBAL	zx_cls_wc_callee
	GLOBAL	zx_cls_wc_attr
	GLOBAL	zx_cls_wc_attr_callee
	GLOBAL	zx_cls_wc_pix
	GLOBAL	zx_cls_wc_pix_callee
	GLOBAL	zx_scroll_wc_up
	GLOBAL	zx_scroll_wc_up_callee
	GLOBAL	zx_scroll_wc_up_attr
	GLOBAL	zx_scroll_wc_up_attr_callee
	GLOBAL	zx_scroll_wc_up_pix
	GLOBAL	zx_scroll_wc_up_pix_callee
	GLOBAL	zx_cxy2saddr
	GLOBAL	zx_cy2saddr
	GLOBAL	zx_px2bitmask
	GLOBAL	zx_pxy2saddr
	GLOBAL	zx_py2saddr
	GLOBAL	zx_saddr2cx
	GLOBAL	zx_saddr2cy
	GLOBAL	zx_saddr2px
	GLOBAL	zx_saddr2py
	GLOBAL	zx_saddr2aaddr
	GLOBAL	zx_saddrcdown
	GLOBAL	zx_saddrcleft
	GLOBAL	zx_saddrcright
	GLOBAL	zx_saddrcup
	GLOBAL	zx_saddrpdown
	GLOBAL	zx_saddrpleft
	GLOBAL	zx_saddrpright
	GLOBAL	zx_saddrpup
	GLOBAL	zx_cxy2saddr_callee
	GLOBAL	zx_pxy2saddr_callee
	GLOBAL	zx_saddr2px_callee
	GLOBAL	zx_saddrpleft_callee
	GLOBAL	zx_saddrpright_callee
	GLOBAL	zx_cxy2aaddr
	GLOBAL	zx_cy2aaddr
	GLOBAL	zx_pxy2aaddr
	GLOBAL	zx_py2aaddr
	GLOBAL	zx_aaddr2cx
	GLOBAL	zx_aaddr2cy
	GLOBAL	zx_aaddr2px
	GLOBAL	zx_aaddr2py
	GLOBAL	zx_aaddr2saddr
	GLOBAL	zx_aaddrcdown
	GLOBAL	zx_aaddrcleft
	GLOBAL	zx_aaddrcright
	GLOBAL	zx_aaddrcup
	GLOBAL	zx_cxy2aaddr_callee
	GLOBAL	zx_pxy2aaddr_callee
	GLOBAL	zx_pattern_fill
	GLOBAL	zx_pattern_fill_callee
	GLOBAL	im1_init
	GLOBAL	im1_install_isr
	GLOBAL	im1_uninstall_isr
	GLOBAL	nmi_init
	GLOBAL	nmi_install_isr
	GLOBAL	nmi_uninstall_isr
	GLOBAL	add_raster_int
	GLOBAL	tick_count_isr
	GLOBAL	_tick_count
	GLOBAL	zx_im2_init
	GLOBAL	zxgetfname
	GLOBAL	zxgetfname2
	GLOBAL	open
	GLOBAL	creat
	GLOBAL	close
	GLOBAL	read
	GLOBAL	write
	GLOBAL	lseek
	GLOBAL	readbyte
	GLOBAL	writebyte
	GLOBAL	fsync
	GLOBAL	getcwd
	GLOBAL	chdir
	GLOBAL	getwd
	GLOBAL	rmdir
	GLOBAL	__RND_BLOCKSIZE
	GLOBAL	rnd_loadblock
	GLOBAL	rnd_saveblock
	GLOBAL	rnd_erase
	GLOBAL	rnd_erase_fastcall
	GLOBAL	__FOPEN_MAX
	GLOBAL	__sgoioblk
	GLOBAL	__sgoioblk_end
	GLOBAL	fopen_zsock
	GLOBAL	fileno
	GLOBAL	fopen
	GLOBAL	freopen
	GLOBAL	fdopen
	GLOBAL	_freopen1
	GLOBAL	fmemopen
	GLOBAL	funopen
	GLOBAL	fclose
	GLOBAL	fflush
	GLOBAL	closeall
	GLOBAL	fgets
	GLOBAL	fputs
	GLOBAL	fputs_callee
	GLOBAL	fputc
	GLOBAL	fputc_callee
	GLOBAL	fgetc
	GLOBAL	ungetc
	GLOBAL	feof
	GLOBAL	feof_fastcall
	GLOBAL	ferror
	GLOBAL	ferror_fastcall
	GLOBAL	puts
	GLOBAL	ftell
	GLOBAL	fgetpos
	GLOBAL	fseek
	GLOBAL	fread
	GLOBAL	fwrite
	GLOBAL	gets
	GLOBAL	printf
	GLOBAL	fprintf
	GLOBAL	sprintf
	GLOBAL	snprintf
	GLOBAL	vfprintf
	GLOBAL	vsnprintf
	GLOBAL	sprintff
	GLOBAL	snprintff
	GLOBAL	vsnprintff
	GLOBAL	printn
	GLOBAL	scanf
	GLOBAL	fscanf
	GLOBAL	sscanf
	GLOBAL	vfscanf
	GLOBAL	vsscanf
	GLOBAL	getarg
	GLOBAL	fchkstd
	GLOBAL	fgetc_cons
	GLOBAL	fgetc_cons_inkey
	GLOBAL	fputc_cons
	GLOBAL	fgets_cons
	GLOBAL	puts_cons
	GLOBAL	fabandon
	GLOBAL	fdtell
	GLOBAL	fdgetpos
	GLOBAL	rename
	GLOBAL	remove
	GLOBAL	getk
	GLOBAL	getk_inkey
	GLOBAL	printk
	GLOBAL	perror
	GLOBAL	set_fputc_cons
	GLOBAL	fputc_cons_native
	GLOBAL	fputc_cons_generic
	GLOBAL	fputc_cons_ansi


; --- End of Scope Defns ---


; --- End of Compilation ---
