#ifndef __HTTP_BUFFER_H
#define __HTTP_BUFFER_H

#include "http-types.h"

// This function reads a constant number of bytes into the fragment buffer of the http
// transaction object, and returns the number of bytes of the valid data. The number of
// bytes are used in userspace to zero out the garbage we may have read into the buffer.
static __always_inline size_t read_into_buffer(char *buffer, char *data, size_t data_size) {
    __builtin_memset(buffer, 0, HTTP_BUFFER_SIZE);
    if(bpf_probe_read_user(buffer, HTTP_BUFFER_SIZE, data) < 0) {
#if defined(__aarch64__)
#pragma unroll
        for (int i = 0; i < HTTP_BUFFER_SIZE; i++) {
            bpf_probe_read_user(&buffer[i], 1, &data[i]);
            if (buffer[i] == 0) 
                return i;
        }
#endif
    }

    if (data_size < HTTP_BUFFER_SIZE)
	    return data_size;
    else
	    // ensure that the last byte is always
	    // treated as junk in the userspace and 
	    // zeroed out. This prevent a buffer overrun.
	    return HTTP_BUFFER_SIZE-1;

}

#endif
