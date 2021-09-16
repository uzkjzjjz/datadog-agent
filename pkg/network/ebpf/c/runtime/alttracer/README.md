# TCP

`struct sock *` -> `socket_info_t`

`struct sock *` -> `tcp_flow_stats_t`
kernel tracks retransmits + RTT on a `struct sock *`, so `fork`-ed sockets cannot have different stats.

`struct sock *` + `tgid` -> `tcp_flow_t`

`tcp_flow_t` = `tuple_t` + `flow_stats_t`

userspace sockp to flow keys?

on close:
iterate through tuples for sock
associate TCP flow stats to first in list

# UDP

`struct sock *` -> `socket_info_t`

`tuple_t` -> `flow_stats_t`

userspace sockp to tuples?