#ifndef __HTTP_BUFFER_H
#define __HTTP_BUFFER_H

#include "http-types.h"

static __always_inline size_t read_into_buffer(char *buffer, char *data, size_t data_size) {
    __builtin_memset(buffer, 0, HTTP_BUFFER_SIZE);
    int err = bpf_probe_read_user(buffer, HTTP_BUFFER_SIZE, data);
    if (err < 0)
	    return 0;

    if (data_size < HTTP_BUFFER_SIZE)
	    return data_size;
    else
	    return HTTP_BUFFER_SIZE-1;

}

#endif
