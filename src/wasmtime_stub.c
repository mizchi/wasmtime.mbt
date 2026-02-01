#include <moonbit.h>
#include <string.h>
#include "wasmtime_version.h"

moonbit_bytes_t wasmtime_version_bytes() {
  const char *ver = WASMTIME_VERSION;
  size_t len = strlen(ver);
  moonbit_bytes_t result = moonbit_make_bytes((int32_t)len, 0);
  memcpy(result, ver, len);
  return result;
}
