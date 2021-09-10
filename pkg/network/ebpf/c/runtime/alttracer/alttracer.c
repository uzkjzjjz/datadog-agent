#include <linux/kconfig.h>
#include <linux/version.h>
#include <linux/types.h>

#include "inet.h"
#include "sock.h"
#include "tcp.h"
#include "udp.h"

#ifndef LINUX_VERSION_CODE
#error "kernel version not included?"
#endif

__u32 _version SEC("version") = 0xFFFFFFFE;
char _license[] SEC("license") = "GPL";
