#!/bin/sh
#
# Build and start the slip-tun bridge for FUSE.
#
# The fifos are created by slip-tun if they do not already exist and are
# flushed every time FUSE detaches.
#
# Then, in a second console :
#   fuse --rs232-tx=/tmp/tx --rs232-rx=/tmp/rx
#
# Pass -v to slip-tun if you want a log line for every packet.
#
# As well as running the bridge this script sets up the host so that the
# Spectrum can reach the outside world and not just 192.0.2.1 :
#
#   * ip_forward, so the kernel will route between tun0 and the uplink.
#   * MASQUERADE, because 192.0.2.0/24 is TEST-NET-1 and nothing on the
#     internet will route a reply back to it.  Outgoing packets are put on
#     the wire by slip-tun with a raw IP_HDRINCL socket, so they are
#     *locally generated* and only pass through OUTPUT/POSTROUTING - never
#     FORWARD.  POSTROUTING sees them all the same, so the masquerade rule
#     is what makes them leave with the uplink's source address.
#   * FORWARD -o tun0, because the replies do come back the normal way:
#     they arrive on the uplink, conntrack undoes the masquerade back to
#     192.0.2.2, and the kernel then forwards them to tun0.  The -i tun0
#     rule is not needed today (see above) but costs nothing and keeps
#     things working if the raw socket is ever replaced by plain routing.
#
# Rules this script added are removed again when it exits.
#
# A run that does not exit cleanly (killed with -9, terminal closed, machine
# powered off) never gets to run its trap, so it leaves an orphaned slip-tun
# holding $TUN and leaves the firewall rules installed.  On startup we look
# for exactly that and tear it down, because a leftover bridge is not
# something anybody is still using: two bridges cannot share one tun, and the
# stale MASQUERADE/FORWARD rules would otherwise stack up one pair per run.
#
# The teardown is deliberately narrow.  We only kill processes actually called
# slip-tun, and we only delete $TUN if it carries $LOCAL - on a lot of machines
# tun0 belongs to a VPN, and that one is left alone.

TUN=tun0
NET=192.0.2.0/24
LOCAL=192.0.2.1                 # the address slip-tun puts on $TUN

gcc -Wall -O2 slip-tun.c -o slip-tun -DSLIP_ESC_00 || exit 1

# Sanity check only: without a default route there is nothing to masquerade
# out of.  The rule itself matches "any interface except $TUN" rather than
# this one, so that it keeps working if the route moves.
UPLINK=$(ip -o route get 1.1.1.1 2>/dev/null |
         sed -n 's/.* dev \([^ ]*\).*/\1/p')
if [ -z "$UPLINK" ]; then
	echo "No default route, cannot work out the uplink interface." >&2
	exit 1
fi
echo "Masquerading $NET out of everything except $TUN (uplink is $UPLINK)"

# Ask for the sudo password once, up front.  Everything below assumes sudo
# will not stop to prompt: slip-tun runs in the background from here on and
# would be fighting this script for the terminal if it did.
if ! sudo -v; then
	echo "Need sudo to set up tun0 and the firewall rules." >&2
	exit 1
fi

# Delete every copy of one rule that is still installed.  An unclean exit
# leaves its rules behind, and because add_rules() tests with -C before it
# adds, the leftovers would be adopted rather than replaced - so the bridge
# would run on rules nobody removes at the end.  The bound is there so a
# surprise from iptables cannot spin us forever.
purge_rule()
{
	_n=0
	while [ $_n -lt 20 ] && sudo iptables -C "$@" 2>/dev/null; do
		sudo iptables -D "$@" 2>/dev/null || break
		_n=$((_n + 1))
	done
	PURGED=$((PURGED + _n))
}

# Tear down whatever an earlier run left behind.
stale_cleanup()
{
	PURGED=0

	# Any slip-tun alive at this point is an orphan: this script starts
	# its own further down and kills it from the trap on the way out.
	_pids=$(pgrep -x slip-tun 2>/dev/null)
	if [ -n "$_pids" ]; then
		echo "slip-tun from an earlier run is still going (pid" \
		     "$(echo $_pids | tr '\n' ' ' | sed 's/ $//')), stopping it."
		sudo kill $_pids 2>/dev/null
		_i=0
		while [ $_i -lt 50 ] && pgrep -x slip-tun >/dev/null 2>&1; do
			sleep 0.1
			_i=$((_i + 1))
		done
		_pids=$(pgrep -x slip-tun 2>/dev/null)
		[ -n "$_pids" ] && sudo kill -9 $_pids 2>/dev/null
	fi

	purge_rule -t nat POSTROUTING -s "$NET" ! -o "$TUN" -j MASQUERADE
	purge_rule FORWARD -o "$TUN" -j ACCEPT
	purge_rule FORWARD -i "$TUN" -j ACCEPT
	[ "$PURGED" -gt 0 ] &&
		echo "Removed $PURGED leftover firewall rule(s)."

	# slip-tun never makes $TUN persistent, so killing it above is enough
	# to take the device with it.  If something is still there it is not
	# ours unless it carries $LOCAL, and tun0 is a very popular name.
	if ip link show "$TUN" >/dev/null 2>&1; then
		_i=0
		while [ $_i -lt 30 ] && ip link show "$TUN" >/dev/null 2>&1; do
			sleep 0.1
			_i=$((_i + 1))
		done
	fi
	if ip link show "$TUN" >/dev/null 2>&1; then
		if ip -o -4 addr show dev "$TUN" 2>/dev/null |
		   grep -q "inet $LOCAL/"; then
			echo "$TUN is left over from an earlier run, removing it."
			sudo ip link delete "$TUN" 2>/dev/null
		else
			echo "$TUN already exists and does not carry $LOCAL," >&2
			echo "so it is not ours - a VPN most likely." >&2
			echo "Not touching it.  Move this bridge to another" >&2
			echo "device by editing TUN in this script." >&2
			exit 1
		fi
	fi
	if ip link show "$TUN" >/dev/null 2>&1; then
		echo "Could not get rid of $TUN, giving up." >&2
		exit 1
	fi

	return 0
}

stale_cleanup

# Which of the three rules this instance is responsible for removing again.
NAT_ADDED=no
FWD_OUT_ADDED=no
FWD_IN_ADDED=no

# -C tests for the rule, so re-running this script does not stack duplicates.
# The FORWARD rules are inserted at the top so they win over any DROP that
# docker or libvirt may have put in the chain.
add_rules()
{
	sudo sysctl -q -w net.ipv4.ip_forward=1 || return 1

	if ! sudo iptables -t nat -C POSTROUTING -s "$NET" ! -o "$TUN" \
	     -j MASQUERADE 2>/dev/null; then
		sudo iptables -t nat -A POSTROUTING -s "$NET" ! -o "$TUN" \
			-j MASQUERADE || return 1
		NAT_ADDED=yes
	fi

	if ! sudo iptables -C FORWARD -o "$TUN" -j ACCEPT 2>/dev/null; then
		sudo iptables -I FORWARD 1 -o "$TUN" -j ACCEPT || return 1
		FWD_OUT_ADDED=yes
	fi

	if ! sudo iptables -C FORWARD -i "$TUN" -j ACCEPT 2>/dev/null; then
		sudo iptables -I FORWARD 1 -i "$TUN" -j ACCEPT || return 1
		FWD_IN_ADDED=yes
	fi

	return 0
}

del_rules()
{
	[ "$NAT_ADDED" = yes ] &&
	sudo iptables -t nat -D POSTROUTING -s "$NET" ! -o "$TUN" \
		-j MASQUERADE 2>/dev/null
	[ "$FWD_OUT_ADDED" = yes ] &&
	sudo iptables -D FORWARD -o "$TUN" -j ACCEPT 2>/dev/null
	[ "$FWD_IN_ADDED" = yes ] &&
	sudo iptables -D FORWARD -i "$TUN" -j ACCEPT 2>/dev/null
	NAT_ADDED=no
	FWD_OUT_ADDED=no
	FWD_IN_ADDED=no
	return 0
}

# slip-tun runs as root, so it has to be signalled through sudo, which relays
# the SIGTERM on to it.  A background job in a non-interactive shell ignores
# SIGINT, so ^C at the terminal does not reach it and the trap has to.
cleanup()
{
	del_rules
	if [ -n "$SLIP_PID" ]; then
		sudo kill "$SLIP_PID" 2>/dev/null
		wait "$SLIP_PID" 2>/dev/null
		SLIP_PID=
	fi
}

trap 'cleanup; exit 0' INT TERM
trap 'cleanup' EXIT

sudo ./slip-tun "$@" "$TUN" /tmp/rx /tmp/tx &
SLIP_PID=$!

# The rules cannot go in until slip-tun has created the tun device, but they
# have to be in before the Spectrum sends anything: netfilter decides whether
# to NAT a connection when it sees its first packet, and that decision then
# sticks for the life of the conntrack entry.  A connection opened during the
# gap keeps leaving with 192.0.2.2 as its source until it times out.
i=0
while [ $i -lt 50 ]; do
	ip link show "$TUN" >/dev/null 2>&1 && break
	sleep 0.1
	i=$((i + 1))
done

if ! ip link show "$TUN" >/dev/null 2>&1; then
	echo "$TUN never appeared, giving up." >&2
	exit 1
fi

if ! add_rules; then
	echo "Failed to install the firewall rules, giving up." >&2
	echo "The Spectrum would only be able to reach 192.0.2.1." >&2
	exit 1
fi
echo "Firewall rules installed."

wait "$SLIP_PID"
