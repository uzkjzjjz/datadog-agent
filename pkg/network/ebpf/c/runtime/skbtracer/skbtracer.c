#include <linux/kconfig.h>
#include <linux/version.h>
#include <linux/types.h>

#include "recv.h"
#include "udp.h"
#include "tcp.h"
#include "inet.h"
#include "port.h"

#ifndef LINUX_VERSION_CODE
#error "kernel version not included?"
#endif

__u32 _version SEC("version") = 0xFFFFFFFE;
char _license[] SEC("license") = "GPL";
