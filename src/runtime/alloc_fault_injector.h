#ifndef PQCFUZZ_RUNTIME_ALLOC_FAULT_INJECTOR_H
#define PQCFUZZ_RUNTIME_ALLOC_FAULT_INJECTOR_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Allocator fault injector for dedicated binaries built with
// -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc.
//
// Environment contract:
//   PQCFUZZ_ALLOC_FAIL_AT    1-based allocation call index to fail (0 = off)
//   PQCFUZZ_ALLOC_FAIL_COUNT number of consecutive failures (default 1)
void pqcfuzz_alloc_fault_reset(void);
void pqcfuzz_alloc_fault_disarm(void);
// Arms the injector with explicit values (no environment lookup).
void pqcfuzz_alloc_fault_configure(size_t fail_at, size_t fail_count);
size_t pqcfuzz_alloc_fault_calls(void);
size_t pqcfuzz_alloc_fault_failures(void);
int pqcfuzz_alloc_fault_active(void);

void *__wrap_malloc(size_t size);
void *__wrap_calloc(size_t count, size_t size);
void *__wrap_realloc(void *pointer, size_t size);

#ifdef __cplusplus
}
#endif

#endif
