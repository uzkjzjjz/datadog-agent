#ifndef __TCP_H
#define __TCP_H

#include "batch.h"
#include "tracer.h"

#define CONN_BATCH_SIZE 5
#define CONN_BATCHES_PER_CPU 128

BATCH_OBJS(conn_t, CONN_BATCH_SIZE, CONN_BATCHES_PER_CPU)

#endif
