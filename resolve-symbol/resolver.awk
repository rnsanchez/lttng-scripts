#!/usr/bin/awk -f

# Very simple/crude symbol resolver.  Given a bare and standard LTTng-trace output,
# try to resolve addresses into symbols (i.e., function names).  This is a very
# brittle approach: it has served the sole purpose of quickly getting symbols on
# a preliminary tracing session.
#
# Many thanks to LTTng folks, especially Mathieu Desnoyers and Alexandre Montplaisir
# for their continued help.

# Example input:
# [16:15:06.938877460] (+0.000000097) priminho lttng_ust_statedump:bin_info: { cpu_id = 0 }, { baddr = 0x7FBC605F4000, memsz = 2245000, path = "/lib64/ld-2.22.so", is_pic = 1, has_build_id = 0, has_debug_link = 0 }
# [16:15:06.938877723] (+0.000000033) priminho lttng_ust_statedump:bin_info: { cpu_id = 0 }, { baddr = 0x7FBC5E354000, memsz = 2203592, path = "/usr/lib/liblttng-ust-tracepoint.so.0.0.0", is_pic = 1, has_build_id = 0, has_debug_link = 0 }
# [16:15:06.938878030] (+0.000000017) priminho lttng_ust_statedump:bin_info: { cpu_id = 0 }, { baddr = 0x7FBC601D7000, memsz = 2202720, path = "/usr/lib64/varnish/libvarnish.so", is_pic = 1, has_build_id = 0, has_debug_link = 0 }
# [16:15:06.941242105] (+0.001775507) priminho lttng_ust_cyg_profile:func_exit: { cpu_id = 1 }, { addr = 0x4685D0, call_site = 0x46891C }
# [16:15:06.990680765] (+0.010543473) priminho lttng_ust_cyg_profile:func_exit: { cpu_id = 2 }, { addr = 0x7FBC5FBBA760, call_site = 0x7FBC5FBB2C30 }
# [16:15:07.083654965] (+0.001839095) priminho lttng_ust_cyg_profile:func_exit: { cpu_id = 2 }, { addr = 0x7FBC5FBBC300, call_site = 0x7FBC601E4B96 }

# A new image mapping was included: remember it.
$11 ~ /baddr/ {
	# base address and memory size are comma-separated, trim it out.
	baddr[libs] = strtonum(substr($13, 1, length($13) - 1))
	memsz[libs] = strtonum(substr($16, 1, length($16) - 1))
	# path is quoted and comma-separated, trim it out.
	path[libs] = substr($19, 2, length($19) - 3)
	# force cast to number.
	ispic[libs] = substr($22, 1, length($22) - 1) + 0

	# Debug: which lib, and where.
#	printf "Lib: 0x%x +0x%x -- %s\n", baddr[libs], memsz[libs], path[libs]
	libs++
	print
}

# Everything else; just echo it back.
$4 !~ /lttng_ust_cyg_profile/ {
	print
}

# Function enter/exit: try to resolve the addresses.
$4 ~ /lttng_ust_cyg_profile/ {
	# Cast addr and call_site into numbers; can't use +0 because it's hex.
	a = strtonum(substr($13, 1, length($13) - 1))
	c = strtonum($16)

	# First look for a known symbol for addr.
	repl_a = 0
	for (i = 0; i < syms; i++) {
		if (symaddr[i] == a) {
			repl_a = symtab[i]
			break
		}
	}
	if (repl_a == 0) {
		# Not found, check all known images.
		for (i = 0; i < libs; i++) {
			if (a >= baddr[i] && a <= (baddr[i] + memsz[i])) {
				# Found the image; craft a command.
				symaddr[syms] = a
				cmd = sprintf("addr2line -fip -e %s 0x%x | cut -d' ' -f1", path[i], a - baddr[i] * ispic[i])
				# Debug: command about to be launched, over which image,
				# what address, what base address.
#				printf ":: %s -- %s 0x%x 0x%x\n", cmd, path[i], a, baddr[i]
				cmd | getline res
				close(cmd)
				if (res == "??")
					# Symbol could not be resolved.
					res = 0

				symtab[syms] = res
				# Debug: symbol name if found, where (address and image).
#				printf "Sym: %s @ 0x%x -- %s\n", res, a, path[i]
				syms++
			}
		}
	}

	# XXX: copy-paste, do the same for call_site as just done for addr.
	# FIXME: convert to a function.
	repl_c = 0
	for (i = 0; i < syms; i++) {
		if (symaddr[i] == c) {
			repl_c = symtab[i]
			break
		}
	}
	if (repl_c == 0) {
		for (i = 0; i < libs; i++) {
			if (c >= baddr[i] && c <= (baddr[i] + memsz[i])) {
				symaddr[syms] = c
				cmd = sprintf("addr2line -fip -e %s 0x%x | cut -d' ' -f1", path[i], c - baddr[i] * ispic[i])
#				printf ":: %s -- %s 0x%x 0x%x\n", cmd, path[i], c, baddr[i]
				cmd | getline res
				close(cmd)
				if (res == "??")
					res = 0

				symtab[syms] = res
#				printf "Sym: %s @ 0x%x -- %s\n", res, c, path[i]
				syms++
			}
		}
	}

	# In case an address could not be resolved, use the original value.
	if (repl_a == 0)
		repl_a = substr($13, 1, length($13) - 1)
	if (repl_c == 0)
		repl_c = $16

	# XXX: it was simpler to recreate the output just like the only supported
	# input format.  However, this is actually very bad if one needs to extend
	# any kind of functionality.

	# 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000  11111111111111111111111111111111111111111
	# 1                    2              3        4                                5 6      7 8 9  0 1    2 3         4         5 6        7
	# [16:15:06.941242105] (+0.001775507) priminho lttng_ust_cyg_profile:func_exit: { cpu_id = 1 }, { addr = 0x4685D0, call_site = 0x46891C }
	printf "%s %s %s %s { cpu_id = %s }, { addr = %s, call_site = %s }\n", $1, $2, $3, $4, $8, repl_a, repl_c
}
