#include "wasmtime_version.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <time.h>
#if defined(_WIN32)
#include <windows.h>
#endif
#if !defined(_WIN32)
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <dirent.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif
#endif

typedef struct wasm_config_t wasm_config_t;
typedef struct wasm_engine_t wasm_engine_t;
typedef struct wasm_functype_t wasm_functype_t;
typedef struct wasm_valtype_t wasm_valtype_t;
typedef struct wasm_memorytype_t wasm_memorytype_t;
typedef struct wasm_trap_t wasm_trap_t;
typedef struct wasmtime_caller wasmtime_caller_t;
typedef struct wasmtime_context wasmtime_context_t;
typedef struct wasmtime_error wasmtime_error_t;
typedef struct wasmtime_instance_pre wasmtime_instance_pre_t;
typedef struct wasmtime_linker wasmtime_linker_t;
typedef struct wasmtime_module wasmtime_module_t;
typedef struct wasmtime_store wasmtime_store_t;
typedef struct wasmtime_call_future wasmtime_call_future_t;
typedef struct wasi_config_t wasi_config_t;

typedef float float32_t;
typedef double float64_t;

typedef struct wasmtime_func {
  uint64_t store_id;
  void *__private;
} wasmtime_func_t;

typedef struct wasmtime_table {
  struct {
    uint64_t store_id;
    uint32_t __private1;
  };
  uint32_t __private2;
} wasmtime_table_t;

typedef struct wasmtime_memory {
  struct {
    uint64_t store_id;
    uint32_t __private1;
  };
  uint32_t __private2;
} wasmtime_memory_t;

typedef struct wasmtime_global {
  uint64_t store_id;
  uint32_t __private1;
  uint32_t __private2;
  uint32_t __private3;
} wasmtime_global_t;

typedef struct wasmtime_sharedmemory wasmtime_sharedmemory_t;

typedef struct wasmtime_anyref {
  uint64_t store_id;
  uint32_t __private1;
  uint32_t __private2;
  void *__private3;
} wasmtime_anyref_t;

typedef struct wasmtime_externref {
  uint64_t store_id;
  uint32_t __private1;
  uint32_t __private2;
  void *__private3;
} wasmtime_externref_t;

typedef uint8_t wasmtime_valkind_t;

#define WASMTIME_I32 0
#define WASMTIME_I64 1
#define WASMTIME_F32 2
#define WASMTIME_F64 3
#define WASMTIME_V128 4
#define WASMTIME_FUNCREF 5
#define WASMTIME_EXTERNREF 6
#define WASMTIME_ANYREF 7
#ifndef WASM_EXTERNREF
#define WASM_EXTERNREF 128
#endif

typedef uint8_t wasmtime_v128[16];

typedef struct wasm_valtype_vec_t {
  size_t size;
  wasm_valtype_t **data;
} wasm_valtype_vec_t;

typedef union wasmtime_valunion {
  int32_t i32;
  int64_t i64;
  float32_t f32;
  float64_t f64;
  wasmtime_anyref_t anyref;
  wasmtime_externref_t externref;
  wasmtime_func_t funcref;
  wasmtime_v128 v128;
} wasmtime_valunion_t;

typedef struct wasmtime_val {
  wasmtime_valkind_t kind;
  wasmtime_valunion_t of;
} wasmtime_val_t;

typedef struct wasmtime_instance {
  uint64_t store_id;
  size_t __private;
} wasmtime_instance_t;

typedef struct wasm_byte_vec_t {
  size_t size;
  uint8_t *data;
} wasm_byte_vec_t;

typedef uint8_t wasmtime_extern_kind_t;

#define WASMTIME_EXTERN_FUNC 0
#define WASMTIME_EXTERN_GLOBAL 1
#define WASMTIME_EXTERN_TABLE 2
#define WASMTIME_EXTERN_MEMORY 3
#define WASMTIME_EXTERN_SHAREDMEMORY 4

typedef union wasmtime_extern_union {
  wasmtime_func_t func;
  wasmtime_global_t global;
  wasmtime_table_t table;
  wasmtime_memory_t memory;
  wasmtime_sharedmemory_t *sharedmemory;
  uint8_t _padding[32];
} wasmtime_extern_union_t;

typedef struct wasmtime_extern {
  wasmtime_extern_kind_t kind;
  wasmtime_extern_union_t of;
} wasmtime_extern_t;

typedef bool (*wasmtime_func_async_continuation_callback_t)(void *env);

typedef struct wasmtime_async_continuation_t {
  wasmtime_func_async_continuation_callback_t callback;
  void *env;
  void (*finalizer)(void *);
} wasmtime_async_continuation_t;

typedef void (*wasmtime_func_async_callback_t)(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults,
  wasm_trap_t **trap_ret,
  wasmtime_async_continuation_t *continuation_ret
);

typedef wasm_trap_t *(*wasmtime_func_callback_t)(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
);

typedef uint8_t *(*wasmtime_stack_memory_get_callback_t)(
  void *env,
  size_t *out_len
);

typedef struct {
  void *env;
  wasmtime_stack_memory_get_callback_t get_stack_memory;
  void (*finalizer)(void *);
} wasmtime_stack_memory_t;

typedef wasmtime_error_t *(*wasmtime_new_stack_memory_callback_t)(
  void *env,
  size_t size,
  bool zeroed,
  wasmtime_stack_memory_t *stack_ret
);

typedef struct {
  void *env;
  wasmtime_new_stack_memory_callback_t new_stack;
  void (*finalizer)(void *);
} wasmtime_stack_creator_t;
typedef uint8_t *moonbit_bytes_t;

moonbit_bytes_t moonbit_make_bytes(int32_t size, int init);

wasm_engine_t *wasm_engine_new(void);
void wasm_engine_delete(wasm_engine_t *);
void wasm_byte_vec_delete(wasm_byte_vec_t *);

wasmtime_error_t *wasmtime_error_new(const char *);
void wasmtime_error_message(const wasmtime_error_t *, wasm_byte_vec_t *);
bool wasmtime_error_exit_status(const wasmtime_error_t *, int *);
wasm_config_t *wasm_config_new(void);
void wasm_config_delete(wasm_config_t *);
wasm_engine_t *wasm_engine_new_with_config(wasm_config_t *);
wasmtime_error_t *wasmtime_config_target_set(wasm_config_t *, const char *);
wasmtime_error_t *wasmtime_config_cache_config_load(wasm_config_t *, const char *);
void wasmtime_config_cranelift_flag_enable(wasm_config_t *, const char *);
void wasmtime_config_cranelift_flag_set(wasm_config_t *, const char *, const char *);
void wasmtime_config_wasm_threads_set(wasm_config_t *, bool);
void wasmtime_config_shared_memory_set(wasm_config_t *, bool);
void wasmtime_config_wasm_gc_set(wasm_config_t *, bool);
void wasmtime_config_wasm_reference_types_set(wasm_config_t *, bool);
void wasmtime_config_wasm_function_references_set(wasm_config_t *, bool);
wasmtime_store_t *wasmtime_store_new(wasm_engine_t *, void *, void (*)(void *));
void wasmtime_store_delete(wasmtime_store_t *);
wasmtime_context_t *wasmtime_store_context(wasmtime_store_t *);
void wasmtime_error_delete(wasmtime_error_t *);
void wasm_trap_delete(wasm_trap_t *);
void wasmtime_val_unroot(wasmtime_val_t *);
wasm_valtype_t *wasm_valtype_new(uint8_t);
void wasm_valtype_delete(wasm_valtype_t *);
wasmtime_error_t *wasmtime_memorytype_new(
  uint64_t,
  bool,
  uint64_t,
  bool,
  bool,
  uint8_t,
  wasm_memorytype_t **
);
void wasm_memorytype_delete(wasm_memorytype_t *);
wasmtime_error_t *wasmtime_sharedmemory_new(
  const wasm_engine_t *,
  const wasm_memorytype_t *,
  wasmtime_sharedmemory_t **
);
void wasmtime_sharedmemory_delete(wasmtime_sharedmemory_t *);
wasmtime_sharedmemory_t *wasmtime_sharedmemory_clone(const wasmtime_sharedmemory_t *);
uint8_t *wasmtime_sharedmemory_data(const wasmtime_sharedmemory_t *);
size_t wasmtime_sharedmemory_data_size(const wasmtime_sharedmemory_t *);
wasm_functype_t *wasm_functype_new(
  wasm_valtype_vec_t *,
  wasm_valtype_vec_t *
);
void wasm_functype_delete(wasm_functype_t *);
bool wasmtime_call_future_poll(wasmtime_call_future_t *);
void wasmtime_call_future_delete(wasmtime_call_future_t *);
wasmtime_error_t *wasmtime_wat2wasm(const char *, size_t, wasm_byte_vec_t *);
wasmtime_error_t *wasmtime_module_new(
  wasm_engine_t *,
  const uint8_t *,
  size_t,
  wasmtime_module_t **
);
void wasmtime_module_delete(wasmtime_module_t *);
wasmtime_error_t *wasmtime_module_serialize(wasmtime_module_t *, wasm_byte_vec_t *);
wasmtime_error_t *wasmtime_module_deserialize(
  wasm_engine_t *,
  const uint8_t *,
  size_t,
  wasmtime_module_t **
);
wasmtime_error_t *wasmtime_instance_new(
  wasmtime_context_t *,
  const wasmtime_module_t *,
  const wasmtime_extern_t *,
  size_t,
  wasmtime_instance_t *,
  wasm_trap_t **
);
bool wasmtime_instance_export_get(
  wasmtime_context_t *,
  const wasmtime_instance_t *,
  const char *,
  size_t,
  wasmtime_extern_t *
);
void wasmtime_extern_delete(wasmtime_extern_t *);
wasmtime_error_t *wasmtime_func_call(
  wasmtime_context_t *,
  const wasmtime_func_t *,
  const wasmtime_val_t *,
  size_t,
  wasmtime_val_t *,
  size_t,
  wasm_trap_t **
);
wasmtime_context_t *wasmtime_caller_context(wasmtime_caller_t *);
bool wasmtime_externref_new(
  wasmtime_context_t *,
  void *,
  void (*)(void *),
  wasmtime_externref_t *
);
void *wasmtime_externref_data(wasmtime_context_t *, const wasmtime_externref_t *);
void wasmtime_externref_unroot(wasmtime_externref_t *);
wasmtime_linker_t *wasmtime_linker_new(wasm_engine_t *);
void wasmtime_linker_delete(wasmtime_linker_t *);
wasmtime_error_t *wasmtime_linker_define_wasi(wasmtime_linker_t *);
wasmtime_error_t *wasmtime_linker_define(
  wasmtime_linker_t *,
  wasmtime_context_t *,
  const char *,
  size_t,
  const char *,
  size_t,
  const wasmtime_extern_t *
);
wasmtime_error_t *wasmtime_linker_instantiate(
  const wasmtime_linker_t *,
  wasmtime_context_t *,
  const wasmtime_module_t *,
  wasmtime_instance_t *,
  wasm_trap_t **
);
wasi_config_t *wasi_config_new(void);
void wasi_config_delete(wasi_config_t *);
bool wasi_config_set_stdin_file(wasi_config_t *, const char *);
bool wasi_config_set_stdout_file(wasi_config_t *, const char *);
bool wasi_config_set_stderr_file(wasi_config_t *, const char *);
bool wasi_config_set_argv(wasi_config_t *, size_t, const char *[]);
void wasi_config_inherit_argv(wasi_config_t *);
void wasi_config_inherit_stdout(wasi_config_t *);
void wasi_config_inherit_stderr(wasi_config_t *);
void wasi_config_inherit_stdin(wasi_config_t *);
bool wasi_config_preopen_dir(
  wasi_config_t *,
  const char *,
  const char *,
  size_t,
  size_t
);
wasmtime_error_t *wasmtime_context_set_wasi(
  wasmtime_context_t *,
  wasi_config_t *
);
wasmtime_call_future_t *wasmtime_func_call_async(
  wasmtime_context_t *,
  const wasmtime_func_t *,
  const wasmtime_val_t *,
  size_t,
  wasmtime_val_t *,
  size_t,
  wasm_trap_t **,
  wasmtime_error_t **
);
wasmtime_error_t *wasmtime_linker_define_async_func(
  wasmtime_linker_t *,
  const char *,
  size_t,
  const char *,
  size_t,
  const wasm_functype_t *,
  wasmtime_func_async_callback_t,
  void *,
  void (*)(void *)
);
wasmtime_call_future_t *wasmtime_linker_instantiate_async(
  const wasmtime_linker_t *,
  wasmtime_context_t *,
  const wasmtime_module_t *,
  wasmtime_instance_t *,
  wasm_trap_t **,
  wasmtime_error_t **
);
wasmtime_call_future_t *wasmtime_instance_pre_instantiate_async(
  const wasmtime_instance_pre_t *,
  wasmtime_context_t *,
  wasmtime_instance_t *,
  wasm_trap_t **,
  wasmtime_error_t **
);
void wasmtime_config_host_stack_creator_set(wasm_config_t *, wasmtime_stack_creator_t *);
void wasmtime_func_new(
  wasmtime_context_t *,
  const wasm_functype_t *,
  wasmtime_func_callback_t,
  void *,
  void (*)(void *),
  wasmtime_func_t *
);

static char *wasmtime_mbt_copy_cstr(const uint8_t *bytes, int32_t len) {
  if (bytes == NULL || len <= 0) {
    return NULL;
  }
  char *buf = (char *)malloc((size_t)len + 1);
  if (buf == NULL) {
    return NULL;
  }
  memcpy(buf, bytes, (size_t)len);
  buf[len] = '\0';
  return buf;
}

moonbit_bytes_t wasmtime_version_bytes(void) {
  const char *ver = WASMTIME_VERSION;
  int32_t len = (int32_t)strlen(ver);
  moonbit_bytes_t bytes = moonbit_make_bytes(len, 0);
  if (bytes == NULL) {
    return NULL;
  }
  memcpy(bytes, ver, (size_t)len);
  return bytes;
}

wasmtime_error_t *wasmtime_config_target_set_bytes(
  wasm_config_t *config,
  const uint8_t *bytes,
  int32_t len
) {
  char *cstr = wasmtime_mbt_copy_cstr(bytes, len);
  if (len > 0 && cstr == NULL) {
    return wasmtime_error_new("out of memory");
  }
  wasmtime_error_t *err = wasmtime_config_target_set(config, cstr);
  free(cstr);
  return err;
}

wasmtime_error_t *wasmtime_config_cache_config_load_bytes(
  wasm_config_t *config,
  const uint8_t *bytes,
  int32_t len
) {
  char *cstr = wasmtime_mbt_copy_cstr(bytes, len);
  if (len > 0 && cstr == NULL) {
    return wasmtime_error_new("out of memory");
  }
  wasmtime_error_t *err = wasmtime_config_cache_config_load(config, cstr);
  free(cstr);
  return err;
}

void wasmtime_config_cranelift_flag_enable_bytes(
  wasm_config_t *config,
  const uint8_t *bytes,
  int32_t len
) {
  char *cstr = wasmtime_mbt_copy_cstr(bytes, len);
  if (len > 0 && cstr == NULL) {
    return;
  }
  wasmtime_config_cranelift_flag_enable(config, cstr);
  free(cstr);
}

void wasmtime_config_cranelift_flag_set_bytes(
  wasm_config_t *config,
  const uint8_t *key,
  int32_t key_len,
  const uint8_t *value,
  int32_t value_len
) {
  char *key_str = wasmtime_mbt_copy_cstr(key, key_len);
  char *value_str = wasmtime_mbt_copy_cstr(value, value_len);
  if ((key_len > 0 && key_str == NULL) || (value_len > 0 && value_str == NULL)) {
    free(key_str);
    free(value_str);
    return;
  }
  wasmtime_config_cranelift_flag_set(config, key_str, value_str);
  free(key_str);
  free(value_str);
}

bool wasi_config_set_stdin_file_bytes(
  wasi_config_t *config,
  const uint8_t *bytes,
  int32_t len
) {
  char *cstr = wasmtime_mbt_copy_cstr(bytes, len);
  if (len > 0 && cstr == NULL) {
    return false;
  }
  bool ok = wasi_config_set_stdin_file(config, cstr);
  free(cstr);
  return ok;
}

bool wasi_config_set_stdout_file_bytes(
  wasi_config_t *config,
  const uint8_t *bytes,
  int32_t len
) {
  char *cstr = wasmtime_mbt_copy_cstr(bytes, len);
  if (len > 0 && cstr == NULL) {
    return false;
  }
  bool ok = wasi_config_set_stdout_file(config, cstr);
  free(cstr);
  return ok;
}

bool wasi_config_set_stderr_file_bytes(
  wasi_config_t *config,
  const uint8_t *bytes,
  int32_t len
) {
  char *cstr = wasmtime_mbt_copy_cstr(bytes, len);
  if (len > 0 && cstr == NULL) {
    return false;
  }
  bool ok = wasi_config_set_stderr_file(config, cstr);
  free(cstr);
  return ok;
}

bool wasi_config_preopen_dir_bytes(
  wasi_config_t *config,
  const uint8_t *host_path,
  int32_t host_len,
  const uint8_t *guest_path,
  int32_t guest_len,
  size_t dir_perms,
  size_t file_perms
) {
  char *host_cstr = wasmtime_mbt_copy_cstr(host_path, host_len);
  char *guest_cstr = wasmtime_mbt_copy_cstr(guest_path, guest_len);
  if ((host_len > 0 && host_cstr == NULL) || (guest_len > 0 && guest_cstr == NULL)) {
    free(host_cstr);
    free(guest_cstr);
    return false;
  }
  bool ok = wasi_config_preopen_dir(config, host_cstr, guest_cstr, dir_perms, file_perms);
  free(host_cstr);
  free(guest_cstr);
  return ok;
}

wasmtime_store_t *wasmtime_store_new_default(wasm_engine_t *engine) {
  return wasmtime_store_new(engine, NULL, NULL);
}

static void *moonbit_ptr_read_raw(const uint8_t *bytes) {
  if (bytes == NULL) {
    return NULL;
  }
  void *ptr = NULL;
  memcpy(&ptr, bytes, sizeof(ptr));
  return ptr;
}

static void moonbit_ptr_write_raw(uint8_t *bytes, const void *ptr) {
  if (bytes == NULL) {
    return;
  }
  memcpy(bytes, &ptr, sizeof(ptr));
}

bool moonbit_ptr_is_null(const uint8_t *bytes) {
  return moonbit_ptr_read_raw(bytes) == NULL;
}

uint64_t moonbit_ptr_read_u64(const uint8_t *bytes) {
  return (uint64_t)(uintptr_t)moonbit_ptr_read_raw(bytes);
}

uint64_t moonbit_bytes_read_u64(const uint8_t *bytes) {
  if (bytes == NULL) {
    return 0;
  }
  uint64_t value = 0;
  memcpy(&value, bytes, sizeof(value));
  return value;
}

int32_t moonbit_ptr_sizeof(void) {
  return (int32_t)sizeof(void *);
}

void moonbit_ptr_clear(uint8_t *bytes) {
  if (bytes == NULL) {
    return;
  }
  memset(bytes, 0, sizeof(void *));
}

uint64_t moonbit_clock_now_ns(void) {
#if defined(_WIN32)
  LARGE_INTEGER freq;
  LARGE_INTEGER counter;
  if (!QueryPerformanceFrequency(&freq)) {
    return 0;
  }
  if (!QueryPerformanceCounter(&counter)) {
    return 0;
  }
  return (uint64_t)((counter.QuadPart * 1000000000ULL) / freq.QuadPart);
#else
  struct timespec ts;
#if defined(CLOCK_MONOTONIC)
  clock_gettime(CLOCK_MONOTONIC, &ts);
#else
  clock_gettime(CLOCK_REALTIME, &ts);
#endif
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

moonbit_bytes_t moonbit_read_file_bytes(
  const uint8_t *path,
  int32_t path_len,
  uint8_t *error_out
) {
  if (error_out != NULL) {
    memset(error_out, 0, sizeof(void *));
  }
  char *cstr = wasmtime_mbt_copy_cstr(path, path_len);
  if (path_len > 0 && cstr == NULL) {
    wasmtime_error_t *err = wasmtime_error_new("read_file: out of memory");
    if (error_out != NULL) {
      moonbit_ptr_write_raw(error_out, err);
    } else {
      wasmtime_error_delete(err);
    }
    return NULL;
  }
  if (cstr == NULL) {
    wasmtime_error_t *err = wasmtime_error_new("read_file: empty path");
    if (error_out != NULL) {
      moonbit_ptr_write_raw(error_out, err);
    } else {
      wasmtime_error_delete(err);
    }
    return NULL;
  }
  FILE *fp = fopen(cstr, "rb");
  free(cstr);
  if (fp == NULL) {
    wasmtime_error_t *err = wasmtime_error_new("read_file: open failed");
    if (error_out != NULL) {
      moonbit_ptr_write_raw(error_out, err);
    } else {
      wasmtime_error_delete(err);
    }
    return NULL;
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    fclose(fp);
    wasmtime_error_t *err = wasmtime_error_new("read_file: seek failed");
    if (error_out != NULL) {
      moonbit_ptr_write_raw(error_out, err);
    } else {
      wasmtime_error_delete(err);
    }
    return NULL;
  }
  long size_long = ftell(fp);
  if (size_long < 0 || size_long > INT32_MAX) {
    fclose(fp);
    wasmtime_error_t *err = wasmtime_error_new("read_file: size too large");
    if (error_out != NULL) {
      moonbit_ptr_write_raw(error_out, err);
    } else {
      wasmtime_error_delete(err);
    }
    return NULL;
  }
  if (fseek(fp, 0, SEEK_SET) != 0) {
    fclose(fp);
    wasmtime_error_t *err = wasmtime_error_new("read_file: seek failed");
    if (error_out != NULL) {
      moonbit_ptr_write_raw(error_out, err);
    } else {
      wasmtime_error_delete(err);
    }
    return NULL;
  }
  int32_t size = (int32_t)size_long;
  moonbit_bytes_t bytes = moonbit_make_bytes(size, 0);
  if (size > 0 && bytes == NULL) {
    fclose(fp);
    wasmtime_error_t *err = wasmtime_error_new("read_file: alloc failed");
    if (error_out != NULL) {
      moonbit_ptr_write_raw(error_out, err);
    } else {
      wasmtime_error_delete(err);
    }
    return NULL;
  }
  if (size > 0) {
    size_t read_size = fread(bytes, 1, (size_t)size, fp);
    if (read_size != (size_t)size) {
      fclose(fp);
      wasmtime_error_t *err = wasmtime_error_new("read_file: read failed");
      if (error_out != NULL) {
        moonbit_ptr_write_raw(error_out, err);
      } else {
        wasmtime_error_delete(err);
      }
      return NULL;
    }
  }
  fclose(fp);
  return bytes;
}

void wasmtime_error_delete_ptr(const uint8_t *bytes) {
  wasmtime_error_t *err = (wasmtime_error_t *)moonbit_ptr_read_raw(bytes);
  if (err != NULL) {
    wasmtime_error_delete(err);
  }
}

moonbit_bytes_t wasmtime_error_message_bytes(const uint8_t *bytes) {
  wasmtime_error_t *err = (wasmtime_error_t *)moonbit_ptr_read_raw(bytes);
  if (err == NULL) {
    return NULL;
  }
  wasm_byte_vec_t msg = {0, NULL};
  wasmtime_error_message(err, &msg);
  moonbit_bytes_t out = moonbit_make_bytes((int32_t)msg.size, 0);
  if (out != NULL && msg.size > 0) {
    memcpy(out, msg.data, msg.size);
  }
  wasm_byte_vec_delete(&msg);
  return out;
}

void wasm_trap_delete_ptr(const uint8_t *bytes) {
  wasm_trap_t *trap = (wasm_trap_t *)moonbit_ptr_read_raw(bytes);
  if (trap != NULL) {
    wasm_trap_delete(trap);
  }
}

moonbit_bytes_t wasmtime_wat2wasm_bytes(
  const uint8_t *wat,
  int32_t wat_len,
  uint8_t *error_out
) {
  wasm_byte_vec_t wasm = {0, NULL};
  if (error_out != NULL) {
    memset(error_out, 0, sizeof(void *));
  }
  if (wat == NULL || wat_len <= 0) {
    return NULL;
  }
  wasmtime_error_t *err = wasmtime_wat2wasm((const char *)wat, (size_t)wat_len, &wasm);
  if (err != NULL) {
    if (error_out != NULL) {
      moonbit_ptr_write_raw(error_out, err);
    } else {
      wasmtime_error_delete(err);
    }
    return NULL;
  }
  moonbit_bytes_t bytes = moonbit_make_bytes((int32_t)wasm.size, 0);
  if (bytes == NULL) {
    wasm_byte_vec_delete(&wasm);
    return NULL;
  }
  memcpy(bytes, wasm.data, wasm.size);
  wasm_byte_vec_delete(&wasm);
  return bytes;
}

wasmtime_module_t *wasmtime_module_new_bytes(
  wasm_engine_t *engine,
  const uint8_t *wasm,
  int32_t wasm_len,
  uint8_t *error_out
) {
  if (error_out != NULL) {
    memset(error_out, 0, sizeof(void *));
  }
  if (engine == NULL || wasm == NULL || wasm_len <= 0) {
    return NULL;
  }
  wasmtime_module_t *module = NULL;
  wasmtime_error_t *err = wasmtime_module_new(engine, wasm, (size_t)wasm_len, &module);
  if (err != NULL) {
    if (error_out != NULL) {
      moonbit_ptr_write_raw(error_out, err);
    } else {
      wasmtime_error_delete(err);
    }
    return NULL;
  }
  return module;
}

bool wasmtime_linker_instantiate_bytes(
  const wasmtime_linker_t *linker,
  wasmtime_context_t *context,
  const wasmtime_module_t *module,
  uint8_t *instance_bytes,
  uint8_t *trap_out,
  uint8_t *error_out
) {
  wasm_trap_t **trap_ptr = NULL;
  if (trap_out != NULL) {
    memset(trap_out, 0, sizeof(void *));
    trap_ptr = (wasm_trap_t **)trap_out;
  }
  if (error_out != NULL) {
    memset(error_out, 0, sizeof(void *));
  }
  if (instance_bytes == NULL) {
    return false;
  }
  wasmtime_instance_t *instance = (wasmtime_instance_t *)instance_bytes;
  wasmtime_error_t *err = wasmtime_linker_instantiate(linker, context, module, instance, trap_ptr);
  if (err != NULL) {
    if (error_out != NULL) {
      moonbit_ptr_write_raw(error_out, err);
    } else {
      wasmtime_error_delete(err);
    }
    return false;
  }
  return true;
}

bool wasmtime_instance_export_get_func_bytes(
  wasmtime_context_t *context,
  const uint8_t *instance_bytes,
  const uint8_t *name,
  int32_t name_len,
  uint8_t *func_out
) {
  if (instance_bytes == NULL || name == NULL || name_len <= 0 || func_out == NULL) {
    return false;
  }
  wasmtime_extern_t item;
  const wasmtime_instance_t *instance = (const wasmtime_instance_t *)instance_bytes;
  if (!wasmtime_instance_export_get(
        context,
        instance,
        (const char *)name,
        (size_t)name_len,
        &item
      )) {
    return false;
  }
  if (item.kind != WASMTIME_EXTERN_FUNC) {
    wasmtime_extern_delete(&item);
    return false;
  }
  memcpy(func_out, &item.of.func, sizeof(wasmtime_func_t));
  wasmtime_extern_delete(&item);
  return true;
}

bool wasmtime_func_call_bytes(
  wasmtime_context_t *context,
  const uint8_t *func_bytes,
  const uint8_t *args_bytes,
  int32_t nargs,
  uint8_t *results_bytes,
  int32_t nresults,
  uint8_t *trap_out,
  uint8_t *error_out
) {
  const wasmtime_func_t *func = (const wasmtime_func_t *)func_bytes;
  const wasmtime_val_t *args = (const wasmtime_val_t *)args_bytes;
  wasmtime_val_t *results = (wasmtime_val_t *)results_bytes;
  wasm_trap_t **trap_ptr = NULL;
  if (nargs == 0) {
    args = NULL;
  }
  if (nresults == 0) {
    results = NULL;
  }
  if (trap_out != NULL) {
    memset(trap_out, 0, sizeof(void *));
    trap_ptr = (wasm_trap_t **)trap_out;
  }
  if (error_out != NULL) {
    memset(error_out, 0, sizeof(void *));
  }
  wasmtime_error_t *err = wasmtime_func_call(
    context,
    func,
    args,
    (size_t)nargs,
    results,
    (size_t)nresults,
    trap_ptr
  );
  if (err != NULL) {
    if (error_out != NULL) {
      moonbit_ptr_write_raw(error_out, err);
    } else {
      wasmtime_error_delete(err);
    }
    return false;
  }
  return true;
}

int32_t wasmtime_val_sizeof(void) {
  return (int32_t)sizeof(wasmtime_val_t);
}

int32_t wasmtime_instance_sizeof(void) {
  return (int32_t)sizeof(wasmtime_instance_t);
}

int32_t wasmtime_func_sizeof(void) {
  return (int32_t)sizeof(wasmtime_func_t);
}

int32_t wasmtime_stack_creator_sizeof(void) {
  return (int32_t)sizeof(wasmtime_stack_creator_t);
}

static void wasmtime_val_load_at(
  const uint8_t *vals,
  int32_t index,
  wasmtime_val_t *out
) {
  size_t offset = (size_t)index * sizeof(wasmtime_val_t);
  memcpy(out, vals + offset, sizeof(wasmtime_val_t));
}

static void wasmtime_val_store_at(
  uint8_t *vals,
  int32_t index,
  const wasmtime_val_t *val
) {
  size_t offset = (size_t)index * sizeof(wasmtime_val_t);
  memcpy(vals + offset, val, sizeof(wasmtime_val_t));
}

int32_t wasmtime_val_kind_at(const uint8_t *vals, int32_t index) {
  wasmtime_val_t val;
  wasmtime_val_load_at(vals, index, &val);
  return (int32_t)val.kind;
}

void wasmtime_val_set_i32_at(uint8_t *vals, int32_t index, int32_t value) {
  wasmtime_val_t val;
  memset(&val, 0, sizeof(val));
  val.kind = WASMTIME_I32;
  val.of.i32 = value;
  wasmtime_val_store_at(vals, index, &val);
}

void wasmtime_val_set_i64_at(uint8_t *vals, int32_t index, int64_t value) {
  wasmtime_val_t val;
  memset(&val, 0, sizeof(val));
  val.kind = WASMTIME_I64;
  val.of.i64 = value;
  wasmtime_val_store_at(vals, index, &val);
}

void wasmtime_val_set_f32_at(uint8_t *vals, int32_t index, float32_t value) {
  wasmtime_val_t val;
  memset(&val, 0, sizeof(val));
  val.kind = WASMTIME_F32;
  val.of.f32 = value;
  wasmtime_val_store_at(vals, index, &val);
}

void wasmtime_val_set_f64_at(uint8_t *vals, int32_t index, float64_t value) {
  wasmtime_val_t val;
  memset(&val, 0, sizeof(val));
  val.kind = WASMTIME_F64;
  val.of.f64 = value;
  wasmtime_val_store_at(vals, index, &val);
}

int32_t wasmtime_val_get_i32_at(const uint8_t *vals, int32_t index) {
  wasmtime_val_t val;
  wasmtime_val_load_at(vals, index, &val);
  return val.of.i32;
}

int64_t wasmtime_val_get_i64_at(const uint8_t *vals, int32_t index) {
  wasmtime_val_t val;
  wasmtime_val_load_at(vals, index, &val);
  return val.of.i64;
}

float32_t wasmtime_val_get_f32_at(const uint8_t *vals, int32_t index) {
  wasmtime_val_t val;
  wasmtime_val_load_at(vals, index, &val);
  return val.of.f32;
}

float64_t wasmtime_val_get_f64_at(const uint8_t *vals, int32_t index) {
  wasmtime_val_t val;
  wasmtime_val_load_at(vals, index, &val);
  return val.of.f64;
}

void wasmtime_val_unroot_at(uint8_t *vals, int32_t index) {
  wasmtime_val_t val;
  wasmtime_val_load_at(vals, index, &val);
  wasmtime_val_unroot(&val);
  memset(vals + (size_t)index * sizeof(wasmtime_val_t), 0, sizeof(wasmtime_val_t));
}

wasmtime_call_future_t *wasmtime_func_call_async_bytes(
  wasmtime_context_t *context,
  const uint8_t *func_bytes,
  const uint8_t *args_bytes,
  int32_t nargs,
  uint8_t *results_bytes,
  int32_t nresults,
  uint8_t *trap_out,
  uint8_t *error_out
) {
  const wasmtime_func_t *func = (const wasmtime_func_t *)func_bytes;
  const wasmtime_val_t *args = (const wasmtime_val_t *)args_bytes;
  wasmtime_val_t *results = (wasmtime_val_t *)results_bytes;
  wasm_trap_t **trap_ptr = NULL;
  wasmtime_error_t **error_ptr = NULL;
  if (nargs == 0) {
    args = NULL;
  }
  if (nresults == 0) {
    results = NULL;
  }
  if (trap_out != NULL) {
    memset(trap_out, 0, sizeof(void *));
    trap_ptr = (wasm_trap_t **)trap_out;
  }
  if (error_out != NULL) {
    memset(error_out, 0, sizeof(void *));
    error_ptr = (wasmtime_error_t **)error_out;
  }
  wasmtime_call_future_t *future = wasmtime_func_call_async(
    context,
    func,
    args,
    (size_t)nargs,
    results,
    (size_t)nresults,
    trap_ptr,
    error_ptr
  );
  return future;
}

wasmtime_error_t *wasmtime_linker_define_async_func_ptr(
  wasmtime_linker_t *linker,
  const uint8_t *module,
  int32_t module_len,
  const uint8_t *name,
  int32_t name_len,
  const wasm_functype_t *ty,
  uint64_t cb_ptr,
  uint64_t data_ptr,
  uint64_t finalizer_ptr
) {
  wasmtime_func_async_callback_t cb =
    (wasmtime_func_async_callback_t)(uintptr_t)cb_ptr;
  void *data = (void *)(uintptr_t)data_ptr;
  void (*finalizer)(void *) = (void (*)(void *))(uintptr_t)finalizer_ptr;
  return wasmtime_linker_define_async_func(
    linker,
    (const char *)module,
    (size_t)module_len,
    (const char *)name,
    (size_t)name_len,
    ty,
    cb,
    data,
    finalizer
  );
}

wasmtime_call_future_t *wasmtime_linker_instantiate_async_bytes(
  const wasmtime_linker_t *linker,
  wasmtime_context_t *store,
  const wasmtime_module_t *module,
  uint8_t *instance_bytes,
  uint8_t *trap_out,
  uint8_t *error_out
) {
  wasm_trap_t **trap_ptr = NULL;
  wasmtime_error_t **error_ptr = NULL;
  wasmtime_instance_t *instance = (wasmtime_instance_t *)instance_bytes;
  if (trap_out != NULL) {
    memset(trap_out, 0, sizeof(void *));
    trap_ptr = (wasm_trap_t **)trap_out;
  }
  if (error_out != NULL) {
    memset(error_out, 0, sizeof(void *));
    error_ptr = (wasmtime_error_t **)error_out;
  }
  wasmtime_call_future_t *future = wasmtime_linker_instantiate_async(
    linker,
    store,
    module,
    instance,
    trap_ptr,
    error_ptr
  );
  return future;
}

wasmtime_call_future_t *wasmtime_instance_pre_instantiate_async_bytes(
  const wasmtime_instance_pre_t *instance_pre,
  wasmtime_context_t *store,
  uint8_t *instance_bytes,
  uint8_t *trap_out,
  uint8_t *error_out
) {
  wasm_trap_t **trap_ptr = NULL;
  wasmtime_error_t **error_ptr = NULL;
  wasmtime_instance_t *instance = (wasmtime_instance_t *)instance_bytes;
  if (trap_out != NULL) {
    memset(trap_out, 0, sizeof(void *));
    trap_ptr = (wasm_trap_t **)trap_out;
  }
  if (error_out != NULL) {
    memset(error_out, 0, sizeof(void *));
    error_ptr = (wasmtime_error_t **)error_out;
  }
  wasmtime_call_future_t *future = wasmtime_instance_pre_instantiate_async(
    instance_pre,
    store,
    instance,
    trap_ptr,
    error_ptr
  );
  return future;
}

void wasmtime_config_host_stack_creator_set_bytes(
  wasm_config_t *config,
  const uint8_t *creator_bytes
) {
  if (creator_bytes == NULL) {
    return;
  }
  wasmtime_stack_creator_t creator;
  memcpy(&creator, creator_bytes, sizeof(creator));
  wasmtime_config_host_stack_creator_set(config, &creator);
}

void wasmtime_func_new_ptr_bytes(
  wasmtime_context_t *context,
  const wasm_functype_t *ty,
  uint64_t cb_ptr,
  uint64_t data_ptr,
  uint64_t finalizer_ptr,
  uint8_t *func_out
) {
  wasmtime_func_callback_t cb =
    (wasmtime_func_callback_t)(uintptr_t)cb_ptr;
  void *data = (void *)(uintptr_t)data_ptr;
  void (*finalizer)(void *) = (void (*)(void *))(uintptr_t)finalizer_ptr;
  wasmtime_func_t func;
  wasmtime_func_new(context, ty, cb, data, finalizer, &func);
  if (func_out != NULL) {
    memcpy(func_out, &func, sizeof(func));
  }
}

static wasm_valtype_t **wasmtime_mbt_valtype_array_new(
  const uint8_t *kinds,
  int32_t len
) {
  if (len <= 0) {
    return NULL;
  }
  wasm_valtype_t **arr = (wasm_valtype_t **)malloc(sizeof(wasm_valtype_t *) * (size_t)len);
  if (arr == NULL) {
    return NULL;
  }
  for (int32_t i = 0; i < len; i++) {
    arr[i] = wasm_valtype_new(kinds[i]);
    if (arr[i] == NULL) {
      for (int32_t j = 0; j < i; j++) {
        wasm_valtype_delete(arr[j]);
      }
      free(arr);
      return NULL;
    }
  }
  return arr;
}

static void wasmtime_mbt_valtype_array_delete(wasm_valtype_t **arr, int32_t len) {
  if (arr == NULL) {
    return;
  }
  for (int32_t i = 0; i < len; i++) {
    wasm_valtype_delete(arr[i]);
  }
  free(arr);
}

wasm_functype_t *wasmtime_functype_new_from_kinds(
  const uint8_t *params,
  int32_t nparams,
  const uint8_t *results,
  int32_t nresults
) {
  wasm_valtype_t **params_arr = wasmtime_mbt_valtype_array_new(params, nparams);
  if (nparams > 0 && params_arr == NULL) {
    return NULL;
  }
  wasm_valtype_t **results_arr = wasmtime_mbt_valtype_array_new(results, nresults);
  if (nresults > 0 && results_arr == NULL) {
    wasmtime_mbt_valtype_array_delete(params_arr, nparams);
    return NULL;
  }
  wasm_valtype_vec_t params_vec = {
    .size = (size_t)(nparams < 0 ? 0 : nparams),
    .data = params_arr
  };
  wasm_valtype_vec_t results_vec = {
    .size = (size_t)(nresults < 0 ? 0 : nresults),
    .data = results_arr
  };
  wasm_functype_t *ty = wasm_functype_new(&params_vec, &results_vec);
  if (ty == NULL) {
    wasmtime_mbt_valtype_array_delete(params_arr, nparams);
    wasmtime_mbt_valtype_array_delete(results_arr, nresults);
  }
  return ty;
}

static wasm_trap_t *wasmtime_mbt_noop_callback(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)env;
  (void)caller;
  (void)args;
  (void)nargs;
  (void)results;
  (void)nresults;
  return NULL;
}

uint64_t wasmtime_noop_callback_ptr(void) {
  return (uint64_t)(uintptr_t)&wasmtime_mbt_noop_callback;
}

static uint8_t *wasmtime_spectest_buf = NULL;
static size_t wasmtime_spectest_len = 0;
static size_t wasmtime_spectest_cap = 0;

static void wasmtime_spectest_capture_push(uint8_t value) {
  if (wasmtime_spectest_len + 1 > wasmtime_spectest_cap) {
    size_t next_cap = wasmtime_spectest_cap == 0 ? 64 : wasmtime_spectest_cap * 2;
    uint8_t *next = (uint8_t *)realloc(wasmtime_spectest_buf, next_cap);
    if (next == NULL) {
      return;
    }
    wasmtime_spectest_buf = next;
    wasmtime_spectest_cap = next_cap;
  }
  wasmtime_spectest_buf[wasmtime_spectest_len] = value;
  wasmtime_spectest_len += 1;
}

static wasm_trap_t *wasmtime_mbt_spectest_print_char(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)env;
  (void)caller;
  (void)results;
  (void)nresults;
  if (args != NULL && nargs > 0) {
    uint8_t value = (uint8_t)(args[0].of.i32 & 0xff);
    wasmtime_spectest_capture_push(value);
  }
  return NULL;
}

moonbit_bytes_t wasmtime_spectest_capture_bytes(void) {
  moonbit_bytes_t bytes = moonbit_make_bytes((int32_t)wasmtime_spectest_len, 0);
  if (bytes == NULL) {
    return NULL;
  }
  if (wasmtime_spectest_len > 0 && wasmtime_spectest_buf != NULL) {
    memcpy(bytes, wasmtime_spectest_buf, wasmtime_spectest_len);
  }
  return bytes;
}

void wasmtime_spectest_capture_reset(void) {
  wasmtime_spectest_len = 0;
}

#if !defined(_WIN32)
typedef struct wasmtime_call_future_thread {
  wasmtime_call_future_t *future;
  atomic_bool done;
  int32_t sleep_us;
  pthread_t thread;
} wasmtime_call_future_thread_t;

static void *wasmtime_call_future_thread_main(void *arg) {
  wasmtime_call_future_thread_t *task = (wasmtime_call_future_thread_t *)arg;
  while (!wasmtime_call_future_poll(task->future)) {
    if (task->sleep_us > 0) {
      struct timespec ts;
      ts.tv_sec = (time_t)(task->sleep_us / 1000000);
      ts.tv_nsec = (long)(task->sleep_us % 1000000) * 1000L;
      nanosleep(&ts, NULL);
    } else {
      sched_yield();
    }
  }
  atomic_store(&task->done, true);
  return NULL;
}
#endif

uint64_t wasmtime_call_future_thread_spawn(
  wasmtime_call_future_t *future,
  int32_t poll_sleep_us
) {
#if defined(_WIN32)
  (void)future;
  (void)poll_sleep_us;
  return 0;
#else
  if (future == NULL) {
    return 0;
  }
  wasmtime_call_future_thread_t *task =
    (wasmtime_call_future_thread_t *)malloc(sizeof(wasmtime_call_future_thread_t));
  if (task == NULL) {
    return 0;
  }
  task->future = future;
  task->sleep_us = poll_sleep_us < 0 ? 0 : poll_sleep_us;
  atomic_init(&task->done, false);
  if (pthread_create(&task->thread, NULL, wasmtime_call_future_thread_main, task) != 0) {
    free(task);
    return 0;
  }
  return (uint64_t)(uintptr_t)task;
#endif
}

bool wasmtime_call_future_thread_is_done(uint64_t handle) {
#if defined(_WIN32)
  (void)handle;
  return false;
#else
  if (handle == 0) {
    return false;
  }
  wasmtime_call_future_thread_t *task =
    (wasmtime_call_future_thread_t *)(uintptr_t)handle;
  return atomic_load(&task->done);
#endif
}

bool wasmtime_call_future_thread_join(uint64_t handle) {
#if defined(_WIN32)
  (void)handle;
  return false;
#else
  if (handle == 0) {
    return false;
  }
  wasmtime_call_future_thread_t *task =
    (wasmtime_call_future_thread_t *)(uintptr_t)handle;
  pthread_join(task->thread, NULL);
  free(task);
  return true;
#endif
}

static void wasmtime_bench_error_clear(uint8_t *error_out) {
  if (error_out != NULL) {
    memset(error_out, 0, sizeof(void *));
  }
}

static void wasmtime_bench_error_message(uint8_t *error_out, const char *msg) {
  if (error_out == NULL) {
    return;
  }
  wasmtime_error_t *err = wasmtime_error_new(msg);
  if (err != NULL) {
    moonbit_ptr_write_raw(error_out, err);
  }
}

static void wasmtime_bench_error_take(uint8_t *error_out, wasmtime_error_t *err) {
  if (err == NULL) {
    return;
  }
  if (error_out != NULL) {
    moonbit_ptr_write_raw(error_out, err);
  } else {
    wasmtime_error_delete(err);
  }
}

bool wasmtime_linker_define_spectest_print_char(
  wasmtime_linker_t *linker,
  wasmtime_context_t *context,
  uint8_t *error_out
) {
  wasmtime_bench_error_clear(error_out);
  if (linker == NULL || context == NULL) {
    wasmtime_bench_error_message(error_out, "spectest: linker/context missing");
    return false;
  }
  uint8_t params[1] = { 0 };
  wasm_functype_t *ty = wasmtime_functype_new_from_kinds(params, 1, NULL, 0);
  if (ty == NULL) {
    wasmtime_bench_error_message(error_out, "spectest: functype_new failed");
    return false;
  }
  wasmtime_func_t func;
  wasmtime_func_new(
    context,
    ty,
    wasmtime_mbt_spectest_print_char,
    NULL,
    NULL,
    &func
  );
  wasm_functype_delete(ty);
  wasmtime_extern_t item;
  item.kind = WASMTIME_EXTERN_FUNC;
  item.of.func = func;
  wasmtime_error_t *err = wasmtime_linker_define(
    linker,
    context,
    "spectest",
    8,
    "print_char",
    10,
    &item
  );
  if (err != NULL) {
    wasmtime_bench_error_take(error_out, err);
    return false;
  }
  return true;
}

static void wasmtime_bench_write_u64(uint8_t *bytes, uint64_t value) {
  if (bytes == NULL) {
    return;
  }
  memcpy(bytes, &value, sizeof(value));
}

static void wasmtime_bench_clear_u64(uint8_t *bytes) {
  if (bytes == NULL) {
    return;
  }
  uint64_t zero = 0;
  memcpy(bytes, &zero, sizeof(zero));
}

#if !defined(_WIN32)
enum {
  WASMTIME_BENCH_ERR_NONE = 0,
  WASMTIME_BENCH_ERR_STORE = 1,
  WASMTIME_BENCH_ERR_LINKER = 2,
  WASMTIME_BENCH_ERR_SHARED_CLONE = 3,
  WASMTIME_BENCH_ERR_DEFINE = 4,
  WASMTIME_BENCH_ERR_INSTANTIATE = 5,
  WASMTIME_BENCH_ERR_EXPORT = 6,
  WASMTIME_BENCH_ERR_EXPORT_KIND = 7,
  WASMTIME_BENCH_ERR_CALL = 8
};

static void wasmtime_bench_set_error_code(atomic_int *code, int value) {
  int expected = 0;
  atomic_compare_exchange_strong(code, &expected, value);
}

typedef struct wasmtime_ring_header {
  _Atomic uint32_t head;
  _Atomic uint32_t tail;
  uint64_t sum;
  uint64_t prod_spins;
  uint64_t cons_spins;
} wasmtime_ring_header_t;

static void wasmtime_bench_wait_start(atomic_int *ready_count, atomic_bool *start_flag) {
  if (ready_count == NULL || start_flag == NULL) {
    return;
  }
  atomic_fetch_add_explicit(ready_count, 1, memory_order_release);
  while (!atomic_load_explicit(start_flag, memory_order_acquire)) {
    sched_yield();
  }
}

typedef struct wasmtime_os_ring_thread_args {
  wasmtime_ring_header_t *ring;
  uint32_t *data;
  uint32_t items;
  uint32_t mask;
  atomic_int *ready_count;
  atomic_bool *start_flag;
} wasmtime_os_ring_thread_args_t;

typedef struct wasmtime_os_payload_thread_args {
  wasmtime_ring_header_t *ring;
  uint32_t *data;
  uint32_t items;
  uint32_t mask;
  uint32_t payload_words;
  atomic_int *ready_count;
  atomic_bool *start_flag;
} wasmtime_os_payload_thread_args_t;

static void *wasmtime_os_ring_producer_main(void *arg) {
  wasmtime_os_ring_thread_args_t *args = (wasmtime_os_ring_thread_args_t *)arg;
  wasmtime_bench_wait_start(args->ready_count, args->start_flag);
  wasmtime_ring_header_t *ring = args->ring;
  uint32_t *data = args->data;
  uint32_t mask = args->mask;
  uint32_t capacity = mask + 1;
  uint32_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
  uint64_t spins = 0;
  for (uint32_t i = 0; i < args->items; i++) {
    uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
    while ((head - tail) >= capacity) {
      tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
      sched_yield();
      spins++;
    }
    data[head & mask] = i + 1;
    head = head + 1;
    atomic_store_explicit(&ring->head, head, memory_order_release);
  }
  ring->prod_spins = spins;
  return NULL;
}

static void *wasmtime_os_ring_consumer_main(void *arg) {
  wasmtime_os_ring_thread_args_t *args = (wasmtime_os_ring_thread_args_t *)arg;
  wasmtime_bench_wait_start(args->ready_count, args->start_flag);
  wasmtime_ring_header_t *ring = args->ring;
  uint32_t *data = args->data;
  uint32_t mask = args->mask;
  uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
  uint64_t sum = 0;
  uint64_t spins = 0;
  for (uint32_t i = 0; i < args->items; i++) {
    uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
    while (head == tail) {
      head = atomic_load_explicit(&ring->head, memory_order_acquire);
      sched_yield();
      spins++;
    }
    uint32_t value = data[tail & mask];
    sum += (uint64_t)value;
    tail = tail + 1;
    atomic_store_explicit(&ring->tail, tail, memory_order_release);
  }
  ring->sum = sum;
  ring->cons_spins = spins;
  return NULL;
}

static void *wasmtime_os_payload_producer_main(void *arg) {
  wasmtime_os_payload_thread_args_t *args = (wasmtime_os_payload_thread_args_t *)arg;
  wasmtime_bench_wait_start(args->ready_count, args->start_flag);
  wasmtime_ring_header_t *ring = args->ring;
  uint32_t *data = args->data;
  uint32_t mask = args->mask;
  uint32_t capacity = mask + 1;
  uint32_t payload_words = args->payload_words;
  uint32_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
  uint64_t spins = 0;
  for (uint32_t i = 0; i < args->items; i++) {
    uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
    while ((head - tail) >= capacity) {
      tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
      sched_yield();
      spins++;
    }
    uint32_t base = (head & mask) * payload_words;
    for (uint32_t j = 0; j < payload_words; j++) {
      data[base + j] = i + j + 1;
    }
    head = head + 1;
    atomic_store_explicit(&ring->head, head, memory_order_release);
  }
  ring->prod_spins = spins;
  return NULL;
}

static void *wasmtime_os_payload_consumer_main(void *arg) {
  wasmtime_os_payload_thread_args_t *args = (wasmtime_os_payload_thread_args_t *)arg;
  wasmtime_bench_wait_start(args->ready_count, args->start_flag);
  wasmtime_ring_header_t *ring = args->ring;
  uint32_t *data = args->data;
  uint32_t mask = args->mask;
  uint32_t payload_words = args->payload_words;
  uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
  uint64_t sum = 0;
  uint64_t spins = 0;
  for (uint32_t i = 0; i < args->items; i++) {
    uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
    while (head == tail) {
      head = atomic_load_explicit(&ring->head, memory_order_acquire);
      sched_yield();
      spins++;
    }
    uint32_t base = (tail & mask) * payload_words;
    for (uint32_t j = 0; j < payload_words; j++) {
      sum += (uint64_t)data[base + j];
    }
    tail = tail + 1;
    atomic_store_explicit(&ring->tail, tail, memory_order_release);
  }
  ring->sum = sum;
  ring->cons_spins = spins;
  return NULL;
}

typedef struct wasmtime_wasm_ring_thread_args {
  wasm_engine_t *engine;
  wasmtime_module_t *module;
  wasmtime_sharedmemory_t *shared;
  uint32_t items;
  uint32_t mask;
  const char *func_name;
  size_t func_name_len;
  atomic_int *error_code;
  atomic_int *ready_count;
  atomic_bool *start_flag;
} wasmtime_wasm_ring_thread_args_t;

static void *wasmtime_wasm_ring_thread_main(void *arg) {
  wasmtime_wasm_ring_thread_args_t *args = (wasmtime_wasm_ring_thread_args_t *)arg;
  if (atomic_load(args->error_code) != 0) {
    return NULL;
  }
  wasmtime_store_t *store = wasmtime_store_new(args->engine, NULL, NULL);
  if (store == NULL) {
    wasmtime_bench_set_error_code(args->error_code, WASMTIME_BENCH_ERR_STORE);
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_store_context(store);
  wasmtime_linker_t *linker = wasmtime_linker_new(args->engine);
  if (linker == NULL) {
    wasmtime_store_delete(store);
    wasmtime_bench_set_error_code(args->error_code, WASMTIME_BENCH_ERR_LINKER);
    return NULL;
  }
  wasmtime_sharedmemory_t *shared = wasmtime_sharedmemory_clone(args->shared);
  if (shared == NULL) {
    wasmtime_linker_delete(linker);
    wasmtime_store_delete(store);
    wasmtime_bench_set_error_code(args->error_code, WASMTIME_BENCH_ERR_SHARED_CLONE);
    return NULL;
  }
  wasmtime_extern_t mem_extern;
  mem_extern.kind = WASMTIME_EXTERN_SHAREDMEMORY;
  mem_extern.of.sharedmemory = shared;
  wasmtime_error_t *err = wasmtime_linker_define(
    linker,
    context,
    "env",
    3,
    "mem",
    3,
    &mem_extern
  );
  if (err != NULL) {
    wasmtime_error_delete(err);
    wasmtime_sharedmemory_delete(shared);
    wasmtime_linker_delete(linker);
    wasmtime_store_delete(store);
    wasmtime_bench_set_error_code(args->error_code, WASMTIME_BENCH_ERR_DEFINE);
    return NULL;
  }
  wasmtime_instance_t instance;
  wasm_trap_t *trap = NULL;
  err = wasmtime_linker_instantiate(linker, context, args->module, &instance, &trap);
  if (trap != NULL) {
    wasm_trap_delete(trap);
  }
  if (err != NULL || trap != NULL) {
    if (err != NULL) {
      wasmtime_error_delete(err);
    }
    wasmtime_sharedmemory_delete(shared);
    wasmtime_linker_delete(linker);
    wasmtime_store_delete(store);
    wasmtime_bench_set_error_code(args->error_code, WASMTIME_BENCH_ERR_INSTANTIATE);
    return NULL;
  }
  wasmtime_extern_t item;
  if (!wasmtime_instance_export_get(
        context,
        &instance,
        args->func_name,
        args->func_name_len,
        &item
      )) {
    wasmtime_sharedmemory_delete(shared);
    wasmtime_linker_delete(linker);
    wasmtime_store_delete(store);
    wasmtime_bench_set_error_code(args->error_code, WASMTIME_BENCH_ERR_EXPORT);
    return NULL;
  }
  if (item.kind != WASMTIME_EXTERN_FUNC) {
    wasmtime_extern_delete(&item);
    wasmtime_sharedmemory_delete(shared);
    wasmtime_linker_delete(linker);
    wasmtime_store_delete(store);
    wasmtime_bench_set_error_code(args->error_code, WASMTIME_BENCH_ERR_EXPORT_KIND);
    return NULL;
  }
  wasmtime_func_t func = item.of.func;
  wasmtime_bench_wait_start(args->ready_count, args->start_flag);
  wasmtime_val_t argv[2];
  argv[0].kind = WASMTIME_I32;
  argv[0].of.i32 = (int32_t)args->items;
  argv[1].kind = WASMTIME_I32;
  argv[1].of.i32 = (int32_t)args->mask;
  trap = NULL;
  err = wasmtime_func_call(context, &func, argv, 2, NULL, 0, &trap);
  if (trap != NULL) {
    wasm_trap_delete(trap);
  }
  wasmtime_extern_delete(&item);
  if (err != NULL || trap != NULL) {
    if (err != NULL) {
      wasmtime_error_delete(err);
    }
    wasmtime_sharedmemory_delete(shared);
    wasmtime_linker_delete(linker);
    wasmtime_store_delete(store);
    wasmtime_bench_set_error_code(args->error_code, WASMTIME_BENCH_ERR_CALL);
    return NULL;
  }
  wasmtime_sharedmemory_delete(shared);
  wasmtime_linker_delete(linker);
  wasmtime_store_delete(store);
  return NULL;
}

typedef struct wasmtime_thread_runtime {
  wasm_engine_t *engine;
  wasmtime_sharedmemory_t *shared;
  uint64_t pages;
  char *wasi_preopen_host;
  char *wasi_preopen_guest;
  int wasi_dir_perms;
  int wasi_file_perms;
  bool wasi_inherit_stdio;
  bool wasi_inherit_argv;
  char **wasi_argv;
  size_t wasi_argc;
} wasmtime_thread_runtime_t;

typedef struct wasmtime_thread_task {
  pthread_t thread;
  wasmtime_thread_runtime_t *runtime;
  wasmtime_module_t *module;
  char *func_name;
  size_t func_name_len;
  wasmtime_val_t *args;
  size_t nargs;
  size_t repeat;
  wasmtime_error_t *error;
  atomic_bool done;
  atomic_bool detached;
  atomic_bool collected;
} wasmtime_thread_task_t;

typedef struct mbt_string {
  uint16_t *data;
  size_t len;
} mbt_string_t;

typedef struct mbt_string_builder {
  uint16_t *data;
  size_t len;
  size_t cap;
} mbt_string_builder_t;

typedef struct mbt_string_read {
  const mbt_string_t *str;
  size_t index;
} mbt_string_read_t;

typedef struct mbt_string_array {
  char **items;
  size_t len;
} mbt_string_array_t;

typedef struct mbt_string_array_read {
  const mbt_string_array_t *arr;
  size_t index;
} mbt_string_array_read_t;

typedef struct mbt_byte_array {
  uint8_t *data;
  size_t len;
} mbt_byte_array_t;

typedef struct mbt_byte_array_builder {
  uint8_t *data;
  size_t len;
  size_t cap;
} mbt_byte_array_builder_t;

typedef struct mbt_byte_array_read {
  const mbt_byte_array_t *arr;
  size_t index;
} mbt_byte_array_read_t;

typedef struct mbt_fs_host {
  wasmtime_thread_runtime_t *runtime;
  char *error_message;
  uint8_t *last_file;
  size_t last_file_len;
  char **last_dir_entries;
  size_t last_dir_len;
} mbt_fs_host_t;

static mbt_string_t *mbt_string_new(uint16_t *data, size_t len) {
  mbt_string_t *s = (mbt_string_t *)malloc(sizeof(mbt_string_t));
  if (s == NULL) {
    free(data);
    return NULL;
  }
  s->data = data;
  s->len = len;
  return s;
}

static mbt_string_t *mbt_string_from_utf16(const uint16_t *data, size_t len) {
  uint16_t *buf = NULL;
  if (len > 0) {
    buf = (uint16_t *)malloc(sizeof(uint16_t) * len);
    if (buf == NULL) {
      return NULL;
    }
    memcpy(buf, data, sizeof(uint16_t) * len);
  }
  return mbt_string_new(buf, len);
}

static mbt_string_t *mbt_string_from_utf8(const char *s) {
  if (s == NULL) {
    return mbt_string_new(NULL, 0);
  }
  size_t len = strlen(s);
  uint16_t *buf = (uint16_t *)malloc(sizeof(uint16_t) * (len + 1));
  if (buf == NULL) {
    return NULL;
  }
  size_t out_len = 0;
  size_t i = 0;
  while (i < len) {
    uint8_t c = (uint8_t)s[i];
    uint32_t code = 0;
    size_t extra = 0;
    if (c < 0x80) {
      code = c;
      extra = 0;
    } else if ((c & 0xE0) == 0xC0 && i + 1 < len) {
      code = ((uint32_t)(c & 0x1F) << 6) | (uint32_t)(s[i + 1] & 0x3F);
      extra = 1;
    } else if ((c & 0xF0) == 0xE0 && i + 2 < len) {
      code = ((uint32_t)(c & 0x0F) << 12) |
             ((uint32_t)(s[i + 1] & 0x3F) << 6) |
             (uint32_t)(s[i + 2] & 0x3F);
      extra = 2;
    } else if ((c & 0xF8) == 0xF0 && i + 3 < len) {
      code = ((uint32_t)(c & 0x07) << 18) |
             ((uint32_t)(s[i + 1] & 0x3F) << 12) |
             ((uint32_t)(s[i + 2] & 0x3F) << 6) |
             (uint32_t)(s[i + 3] & 0x3F);
      extra = 3;
    } else {
      code = 0xFFFD;
      extra = 0;
    }
    i += extra + 1;
    if (code <= 0xFFFF) {
      buf[out_len++] = (uint16_t)code;
    } else {
      code -= 0x10000;
      buf[out_len++] = (uint16_t)(0xD800 + (code >> 10));
      buf[out_len++] = (uint16_t)(0xDC00 + (code & 0x3FF));
    }
  }
  return mbt_string_new(buf, out_len);
}

static char *mbt_string_to_utf8(const mbt_string_t *s) {
  if (s == NULL || s->len == 0) {
    char *out = (char *)malloc(1);
    if (out != NULL) {
      out[0] = '\0';
    }
    return out;
  }
  size_t cap = s->len * 4 + 1;
  char *out = (char *)malloc(cap);
  if (out == NULL) {
    return NULL;
  }
  size_t out_len = 0;
  size_t i = 0;
  while (i < s->len) {
    uint32_t code = s->data[i];
    if (code >= 0xD800 && code <= 0xDBFF && i + 1 < s->len) {
      uint32_t low = s->data[i + 1];
      if (low >= 0xDC00 && low <= 0xDFFF) {
        code = 0x10000 + (((code - 0xD800) << 10) | (low - 0xDC00));
        i += 1;
      }
    }
    if (code <= 0x7F) {
      out[out_len++] = (char)code;
    } else if (code <= 0x7FF) {
      out[out_len++] = (char)(0xC0 | (code >> 6));
      out[out_len++] = (char)(0x80 | (code & 0x3F));
    } else if (code <= 0xFFFF) {
      out[out_len++] = (char)(0xE0 | (code >> 12));
      out[out_len++] = (char)(0x80 | ((code >> 6) & 0x3F));
      out[out_len++] = (char)(0x80 | (code & 0x3F));
    } else {
      out[out_len++] = (char)(0xF0 | (code >> 18));
      out[out_len++] = (char)(0x80 | ((code >> 12) & 0x3F));
      out[out_len++] = (char)(0x80 | ((code >> 6) & 0x3F));
      out[out_len++] = (char)(0x80 | (code & 0x3F));
    }
    i += 1;
  }
  out[out_len] = '\0';
  return out;
}

static void mbt_string_free(void *ptr) {
  mbt_string_t *s = (mbt_string_t *)ptr;
  if (s == NULL) {
    return;
  }
  free(s->data);
  free(s);
}

static mbt_string_builder_t *mbt_string_builder_new(void) {
  mbt_string_builder_t *b =
    (mbt_string_builder_t *)calloc(1, sizeof(mbt_string_builder_t));
  return b;
}

static bool mbt_string_builder_push(mbt_string_builder_t *b, uint16_t ch) {
  if (b == NULL) {
    return false;
  }
  if (b->len + 1 > b->cap) {
    size_t next_cap = b->cap == 0 ? 16 : b->cap * 2;
    uint16_t *next = (uint16_t *)realloc(b->data, next_cap * sizeof(uint16_t));
    if (next == NULL) {
      return false;
    }
    b->data = next;
    b->cap = next_cap;
  }
  b->data[b->len] = ch;
  b->len += 1;
  return true;
}

static mbt_string_t *mbt_string_builder_finish(mbt_string_builder_t *b) {
  if (b == NULL) {
    return NULL;
  }
  mbt_string_t *s = mbt_string_new(b->data, b->len);
  free(b);
  return s;
}

static void mbt_string_builder_free(mbt_string_builder_t *b) {
  if (b == NULL) {
    return;
  }
  free(b->data);
  free(b);
}

static mbt_byte_array_t *mbt_byte_array_new(const uint8_t *data, size_t len) {
  uint8_t *buf = NULL;
  if (len > 0) {
    buf = (uint8_t *)malloc(len);
    if (buf == NULL) {
      return NULL;
    }
    memcpy(buf, data, len);
  }
  mbt_byte_array_t *arr = (mbt_byte_array_t *)malloc(sizeof(mbt_byte_array_t));
  if (arr == NULL) {
    free(buf);
    return NULL;
  }
  arr->data = buf;
  arr->len = len;
  return arr;
}

static void mbt_byte_array_free(void *ptr) {
  mbt_byte_array_t *arr = (mbt_byte_array_t *)ptr;
  if (arr == NULL) {
    return;
  }
  free(arr->data);
  free(arr);
}

static mbt_byte_array_builder_t *mbt_byte_array_builder_new(void) {
  mbt_byte_array_builder_t *b =
    (mbt_byte_array_builder_t *)calloc(1, sizeof(mbt_byte_array_builder_t));
  return b;
}

static bool mbt_byte_array_builder_push(mbt_byte_array_builder_t *b, uint8_t ch) {
  if (b == NULL) {
    return false;
  }
  if (b->len + 1 > b->cap) {
    size_t next_cap = b->cap == 0 ? 64 : b->cap * 2;
    uint8_t *next = (uint8_t *)realloc(b->data, next_cap);
    if (next == NULL) {
      return false;
    }
    b->data = next;
    b->cap = next_cap;
  }
  b->data[b->len] = ch;
  b->len += 1;
  return true;
}

static mbt_byte_array_t *mbt_byte_array_builder_finish(mbt_byte_array_builder_t *b) {
  if (b == NULL) {
    return NULL;
  }
  mbt_byte_array_t *arr = (mbt_byte_array_t *)malloc(sizeof(mbt_byte_array_t));
  if (arr == NULL) {
    free(b->data);
    free(b);
    return NULL;
  }
  arr->data = b->data;
  arr->len = b->len;
  free(b);
  return arr;
}

static void mbt_byte_array_builder_free(mbt_byte_array_builder_t *b) {
  if (b == NULL) {
    return;
  }
  free(b->data);
  free(b);
}

static mbt_string_array_t *mbt_string_array_new(char **items, size_t len) {
  mbt_string_array_t *arr = (mbt_string_array_t *)malloc(sizeof(mbt_string_array_t));
  if (arr == NULL) {
    return NULL;
  }
  arr->items = items;
  arr->len = len;
  return arr;
}

static void mbt_string_array_free(void *ptr) {
  mbt_string_array_t *arr = (mbt_string_array_t *)ptr;
  if (arr == NULL) {
    return;
  }
  if (arr->items != NULL) {
    for (size_t i = 0; i < arr->len; i++) {
      free(arr->items[i]);
    }
    free(arr->items);
  }
  free(arr);
}

static void mbt_fs_clear_error(mbt_fs_host_t *host) {
  if (host == NULL) {
    return;
  }
  if (host->error_message != NULL) {
    free(host->error_message);
  }
  host->error_message = strdup("");
}

static void mbt_fs_set_error(mbt_fs_host_t *host, const char *msg) {
  if (host == NULL) {
    return;
  }
  if (host->error_message != NULL) {
    free(host->error_message);
  }
  if (msg == NULL) {
    host->error_message = strdup("");
  } else {
    host->error_message = strdup(msg);
  }
}

static void mbt_fs_set_errno(mbt_fs_host_t *host, const char *context) {
  const char *err = strerror(errno);
  if (context == NULL || context[0] == '\0') {
    mbt_fs_set_error(host, err);
    return;
  }
  char buf[256];
  snprintf(buf, sizeof(buf), "%s: %s", context, err);
  mbt_fs_set_error(host, buf);
}

static void mbt_fs_clear_file(mbt_fs_host_t *host) {
  if (host == NULL) {
    return;
  }
  free(host->last_file);
  host->last_file = NULL;
  host->last_file_len = 0;
}

static void mbt_fs_clear_dir(mbt_fs_host_t *host) {
  if (host == NULL) {
    return;
  }
  if (host->last_dir_entries != NULL) {
    for (size_t i = 0; i < host->last_dir_len; i++) {
      free(host->last_dir_entries[i]);
    }
    free(host->last_dir_entries);
  }
  host->last_dir_entries = NULL;
  host->last_dir_len = 0;
}

static mbt_fs_host_t *mbt_fs_host_new(wasmtime_thread_runtime_t *runtime) {
  mbt_fs_host_t *host = (mbt_fs_host_t *)calloc(1, sizeof(mbt_fs_host_t));
  if (host == NULL) {
    return NULL;
  }
  host->runtime = runtime;
  host->error_message = strdup("");
  return host;
}

static void mbt_fs_host_free(mbt_fs_host_t *host) {
  if (host == NULL) {
    return;
  }
  mbt_fs_clear_file(host);
  mbt_fs_clear_dir(host);
  if (host->error_message != NULL) {
    free(host->error_message);
  }
  free(host);
}

static char *mbt_fs_resolve_path(mbt_fs_host_t *host, const char *guest_path) {
  if (guest_path == NULL) {
    return NULL;
  }
  const char *root = NULL;
  if (host != NULL && host->runtime != NULL) {
    root = host->runtime->wasi_preopen_host;
  }
  if (root == NULL || guest_path[0] == '/') {
    return strdup(guest_path);
  }
  size_t root_len = strlen(root);
  size_t path_len = strlen(guest_path);
  bool need_sep = root_len > 0 && root[root_len - 1] != '/';
  size_t total = root_len + (need_sep ? 1 : 0) + path_len + 1;
  char *out = (char *)malloc(total);
  if (out == NULL) {
    return NULL;
  }
  memcpy(out, root, root_len);
  size_t pos = root_len;
  if (need_sep) {
    out[pos++] = '/';
  }
  memcpy(out + pos, guest_path, path_len);
  out[pos + path_len] = '\0';
  return out;
}

static void *mbt_externref_data(wasmtime_context_t *context, const wasmtime_val_t *val) {
  if (context == NULL || val == NULL) {
    return NULL;
  }
  if (val->kind != WASMTIME_EXTERNREF) {
    return NULL;
  }
  if (val->of.externref.store_id == 0) {
    return NULL;
  }
  return wasmtime_externref_data(context, &val->of.externref);
}

static bool mbt_set_externref_result(
  wasmtime_caller_t *caller,
  wasmtime_val_t *results,
  size_t nresults,
  void *data,
  void (*finalizer)(void *)
) {
  if (results == NULL || nresults == 0) {
    if (finalizer != NULL) {
      finalizer(data);
    }
    return false;
  }
  if (data == NULL) {
    memset(&results[0].of.externref, 0, sizeof(results[0].of.externref));
    results[0].kind = WASMTIME_EXTERNREF;
    return false;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  if (context == NULL) {
    if (finalizer != NULL) {
      finalizer(data);
    }
    return false;
  }
  wasmtime_externref_t ref;
  if (!wasmtime_externref_new(context, data, finalizer, &ref)) {
    if (finalizer != NULL) {
      finalizer(data);
    }
    return false;
  }
  results[0].kind = WASMTIME_EXTERNREF;
  results[0].of.externref = ref;
  return true;
}

static void mbt_set_i32_result(wasmtime_val_t *results, size_t nresults, int32_t value) {
  if (results == NULL || nresults == 0) {
    return;
  }
  results[0].kind = WASMTIME_I32;
  results[0].of.i32 = value;
}

static wasm_trap_t *mbt_fs_begin_create_string(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)env;
  (void)args;
  (void)nargs;
  mbt_string_builder_t *builder = mbt_string_builder_new();
  if (builder == NULL) {
    return NULL;
  }
  mbt_set_externref_result(caller, results, nresults, builder, NULL);
  return NULL;
}

static wasm_trap_t *mbt_fs_string_append_char(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)env;
  (void)caller;
  (void)results;
  (void)nresults;
  if (args == NULL || nargs < 2) {
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  mbt_string_builder_t *builder =
    (mbt_string_builder_t *)mbt_externref_data(context, &args[0]);
  uint16_t ch = (uint16_t)(args[1].of.i32 & 0xFFFF);
  if (builder != NULL) {
    mbt_string_builder_push(builder, ch);
  }
  return NULL;
}

static wasm_trap_t *mbt_fs_finish_create_string(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)env;
  if (args == NULL || nargs < 1) {
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  mbt_string_builder_t *builder =
    (mbt_string_builder_t *)mbt_externref_data(context, &args[0]);
  mbt_string_t *str = mbt_string_builder_finish(builder);
  if (str == NULL) {
    str = mbt_string_new(NULL, 0);
  }
  mbt_set_externref_result(caller, results, nresults, str, mbt_string_free);
  return NULL;
}

static wasm_trap_t *mbt_fs_begin_read_string(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)env;
  if (args == NULL || nargs < 1) {
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  const mbt_string_t *str =
    (const mbt_string_t *)mbt_externref_data(context, &args[0]);
  mbt_string_read_t *handle =
    (mbt_string_read_t *)calloc(1, sizeof(mbt_string_read_t));
  if (handle == NULL) {
    return NULL;
  }
  handle->str = str;
  handle->index = 0;
  mbt_set_externref_result(caller, results, nresults, handle, NULL);
  return NULL;
}

static wasm_trap_t *mbt_fs_string_read_char(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)env;
  if (args == NULL || nargs < 1) {
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  mbt_string_read_t *handle =
    (mbt_string_read_t *)mbt_externref_data(context, &args[0]);
  if (handle == NULL || handle->str == NULL || handle->index >= handle->str->len) {
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  int32_t ch = (int32_t)handle->str->data[handle->index];
  handle->index += 1;
  mbt_set_i32_result(results, nresults, ch);
  return NULL;
}

static wasm_trap_t *mbt_fs_finish_read_string(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)env;
  (void)results;
  (void)nresults;
  if (args == NULL || nargs < 1) {
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  mbt_string_read_t *handle =
    (mbt_string_read_t *)mbt_externref_data(context, &args[0]);
  free(handle);
  return NULL;
}

static wasm_trap_t *mbt_fs_begin_create_byte_array(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)env;
  (void)args;
  (void)nargs;
  mbt_byte_array_builder_t *builder = mbt_byte_array_builder_new();
  if (builder == NULL) {
    return NULL;
  }
  mbt_set_externref_result(caller, results, nresults, builder, NULL);
  return NULL;
}

static wasm_trap_t *mbt_fs_byte_array_append_byte(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)env;
  (void)caller;
  (void)results;
  (void)nresults;
  if (args == NULL || nargs < 2) {
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  mbt_byte_array_builder_t *builder =
    (mbt_byte_array_builder_t *)mbt_externref_data(context, &args[0]);
  uint8_t ch = (uint8_t)(args[1].of.i32 & 0xFF);
  if (builder != NULL) {
    mbt_byte_array_builder_push(builder, ch);
  }
  return NULL;
}

static wasm_trap_t *mbt_fs_finish_create_byte_array(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)env;
  if (args == NULL || nargs < 1) {
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  mbt_byte_array_builder_t *builder =
    (mbt_byte_array_builder_t *)mbt_externref_data(context, &args[0]);
  mbt_byte_array_t *arr = mbt_byte_array_builder_finish(builder);
  if (arr == NULL) {
    arr = mbt_byte_array_new(NULL, 0);
  }
  mbt_set_externref_result(caller, results, nresults, arr, mbt_byte_array_free);
  return NULL;
}

static wasm_trap_t *mbt_fs_begin_read_byte_array(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)env;
  if (args == NULL || nargs < 1) {
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  const mbt_byte_array_t *arr =
    (const mbt_byte_array_t *)mbt_externref_data(context, &args[0]);
  mbt_byte_array_read_t *handle =
    (mbt_byte_array_read_t *)calloc(1, sizeof(mbt_byte_array_read_t));
  if (handle == NULL) {
    return NULL;
  }
  handle->arr = arr;
  handle->index = 0;
  mbt_set_externref_result(caller, results, nresults, handle, NULL);
  return NULL;
}

static wasm_trap_t *mbt_fs_byte_array_read_byte(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)env;
  if (args == NULL || nargs < 1) {
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  mbt_byte_array_read_t *handle =
    (mbt_byte_array_read_t *)mbt_externref_data(context, &args[0]);
  if (handle == NULL || handle->arr == NULL || handle->index >= handle->arr->len) {
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  int32_t ch = (int32_t)handle->arr->data[handle->index];
  handle->index += 1;
  mbt_set_i32_result(results, nresults, ch);
  return NULL;
}

static wasm_trap_t *mbt_fs_finish_read_byte_array(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)env;
  (void)results;
  (void)nresults;
  if (args == NULL || nargs < 1) {
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  mbt_byte_array_read_t *handle =
    (mbt_byte_array_read_t *)mbt_externref_data(context, &args[0]);
  free(handle);
  return NULL;
}

static wasm_trap_t *mbt_fs_begin_read_string_array(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)env;
  if (args == NULL || nargs < 1) {
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  const mbt_string_array_t *arr =
    (const mbt_string_array_t *)mbt_externref_data(context, &args[0]);
  mbt_string_array_read_t *handle =
    (mbt_string_array_read_t *)calloc(1, sizeof(mbt_string_array_read_t));
  if (handle == NULL) {
    return NULL;
  }
  handle->arr = arr;
  handle->index = 0;
  mbt_set_externref_result(caller, results, nresults, handle, NULL);
  return NULL;
}

static wasm_trap_t *mbt_fs_string_array_read_string(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)env;
  if (args == NULL || nargs < 1) {
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  mbt_string_array_read_t *handle =
    (mbt_string_array_read_t *)mbt_externref_data(context, &args[0]);
  const char *value = "ffi_end_of_/string_array";
  if (handle != NULL && handle->arr != NULL && handle->index < handle->arr->len) {
    value = handle->arr->items[handle->index];
    handle->index += 1;
  }
  mbt_string_t *str = mbt_string_from_utf8(value);
  if (str == NULL) {
    str = mbt_string_new(NULL, 0);
  }
  mbt_set_externref_result(caller, results, nresults, str, mbt_string_free);
  return NULL;
}

static wasm_trap_t *mbt_fs_finish_read_string_array(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)env;
  (void)results;
  (void)nresults;
  if (args == NULL || nargs < 1) {
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  mbt_string_array_read_t *handle =
    (mbt_string_array_read_t *)mbt_externref_data(context, &args[0]);
  free(handle);
  return NULL;
}

static wasm_trap_t *mbt_fs_get_error_message(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)args;
  (void)nargs;
  mbt_fs_host_t *host = (mbt_fs_host_t *)env;
  const char *msg = host != NULL && host->error_message != NULL ? host->error_message : "";
  mbt_string_t *str = mbt_string_from_utf8(msg);
  if (str == NULL) {
    str = mbt_string_new(NULL, 0);
  }
  mbt_set_externref_result(caller, results, nresults, str, mbt_string_free);
  return NULL;
}

static wasm_trap_t *mbt_fs_get_file_content(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)args;
  (void)nargs;
  mbt_fs_host_t *host = (mbt_fs_host_t *)env;
  mbt_byte_array_t *arr = NULL;
  if (host != NULL && host->last_file != NULL && host->last_file_len > 0) {
    arr = mbt_byte_array_new(host->last_file, host->last_file_len);
  } else {
    arr = mbt_byte_array_new(NULL, 0);
  }
  if (arr == NULL) {
    arr = mbt_byte_array_new(NULL, 0);
  }
  mbt_set_externref_result(caller, results, nresults, arr, mbt_byte_array_free);
  return NULL;
}

static wasm_trap_t *mbt_fs_get_dir_files(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)args;
  (void)nargs;
  mbt_fs_host_t *host = (mbt_fs_host_t *)env;
  size_t len = host != NULL ? host->last_dir_len : 0;
  char **items = NULL;
  if (len > 0) {
    items = (char **)calloc(len, sizeof(char *));
    if (items != NULL) {
      for (size_t i = 0; i < len; i++) {
        items[i] = strdup(host->last_dir_entries[i]);
        if (items[i] == NULL) {
          for (size_t j = 0; j < i; j++) {
            free(items[j]);
          }
          free(items);
          items = NULL;
          len = 0;
          break;
        }
      }
    }
  }
  mbt_string_array_t *arr = mbt_string_array_new(items, len);
  if (arr == NULL) {
    if (items != NULL) {
      for (size_t i = 0; i < len; i++) {
        free(items[i]);
      }
      free(items);
    }
    arr = mbt_string_array_new(NULL, 0);
  }
  mbt_set_externref_result(caller, results, nresults, arr, mbt_string_array_free);
  return NULL;
}

static wasm_trap_t *mbt_fs_read_file_to_bytes(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  mbt_fs_host_t *host = (mbt_fs_host_t *)env;
  if (args == NULL || nargs < 1) {
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  const mbt_string_t *path_str =
    (const mbt_string_t *)mbt_externref_data(context, &args[0]);
  if (path_str == NULL) {
    mbt_fs_set_error(host, "fs: invalid path");
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  char *path_utf8 = mbt_string_to_utf8(path_str);
  char *resolved = mbt_fs_resolve_path(host, path_utf8);
  free(path_utf8);
  if (resolved == NULL) {
    mbt_fs_set_error(host, "fs: path resolve failed");
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  FILE *fp = fopen(resolved, "rb");
  if (fp == NULL) {
    mbt_fs_set_errno(host, "fs: open failed");
    free(resolved);
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    mbt_fs_set_errno(host, "fs: seek failed");
    fclose(fp);
    free(resolved);
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  long size = ftell(fp);
  if (size < 0) {
    mbt_fs_set_errno(host, "fs: tell failed");
    fclose(fp);
    free(resolved);
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  if (fseek(fp, 0, SEEK_SET) != 0) {
    mbt_fs_set_errno(host, "fs: seek failed");
    fclose(fp);
    free(resolved);
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  uint8_t *buf = NULL;
  size_t len = (size_t)size;
  if (len > 0) {
    buf = (uint8_t *)malloc(len);
    if (buf == NULL) {
      mbt_fs_set_error(host, "fs: alloc failed");
      fclose(fp);
      free(resolved);
      mbt_set_i32_result(results, nresults, -1);
      return NULL;
    }
    size_t read_len = fread(buf, 1, len, fp);
    if (read_len != len) {
      mbt_fs_set_errno(host, "fs: read failed");
      free(buf);
      fclose(fp);
      free(resolved);
      mbt_set_i32_result(results, nresults, -1);
      return NULL;
    }
  }
  fclose(fp);
  free(resolved);
  mbt_fs_clear_file(host);
  host->last_file = buf;
  host->last_file_len = len;
  mbt_fs_clear_error(host);
  mbt_set_i32_result(results, nresults, 0);
  return NULL;
}

static wasm_trap_t *mbt_fs_write_bytes_to_file(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  mbt_fs_host_t *host = (mbt_fs_host_t *)env;
  if (args == NULL || nargs < 2) {
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  const mbt_string_t *path_str =
    (const mbt_string_t *)mbt_externref_data(context, &args[0]);
  const mbt_byte_array_t *bytes =
    (const mbt_byte_array_t *)mbt_externref_data(context, &args[1]);
  if (path_str == NULL || bytes == NULL) {
    mbt_fs_set_error(host, "fs: invalid args");
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  char *path_utf8 = mbt_string_to_utf8(path_str);
  char *resolved = mbt_fs_resolve_path(host, path_utf8);
  free(path_utf8);
  if (resolved == NULL) {
    mbt_fs_set_error(host, "fs: path resolve failed");
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  FILE *fp = fopen(resolved, "wb");
  if (fp == NULL) {
    mbt_fs_set_errno(host, "fs: open failed");
    free(resolved);
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  size_t written = 0;
  if (bytes->len > 0) {
    written = fwrite(bytes->data, 1, bytes->len, fp);
  }
  if (written != bytes->len) {
    mbt_fs_set_errno(host, "fs: write failed");
    fclose(fp);
    free(resolved);
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  fclose(fp);
  free(resolved);
  mbt_fs_clear_error(host);
  mbt_set_i32_result(results, nresults, 0);
  return NULL;
}

static wasm_trap_t *mbt_fs_path_exists(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)env;
  if (args == NULL || nargs < 1) {
    mbt_set_i32_result(results, nresults, 0);
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  const mbt_string_t *path_str =
    (const mbt_string_t *)mbt_externref_data(context, &args[0]);
  if (path_str == NULL) {
    mbt_set_i32_result(results, nresults, 0);
    return NULL;
  }
  char *path_utf8 = mbt_string_to_utf8(path_str);
  char *resolved = mbt_fs_resolve_path((mbt_fs_host_t *)env, path_utf8);
  free(path_utf8);
  if (resolved == NULL) {
    mbt_set_i32_result(results, nresults, 0);
    return NULL;
  }
  struct stat st;
  int ok = stat(resolved, &st) == 0;
  free(resolved);
  mbt_set_i32_result(results, nresults, ok ? 1 : 0);
  return NULL;
}

static wasm_trap_t *mbt_fs_create_dir(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  mbt_fs_host_t *host = (mbt_fs_host_t *)env;
  if (args == NULL || nargs < 1) {
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  const mbt_string_t *path_str =
    (const mbt_string_t *)mbt_externref_data(context, &args[0]);
  if (path_str == NULL) {
    mbt_fs_set_error(host, "fs: invalid path");
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  char *path_utf8 = mbt_string_to_utf8(path_str);
  char *resolved = mbt_fs_resolve_path(host, path_utf8);
  free(path_utf8);
  if (resolved == NULL) {
    mbt_fs_set_error(host, "fs: path resolve failed");
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  int res = mkdir(resolved, 0777);
  if (res != 0) {
    mbt_fs_set_errno(host, "fs: mkdir failed");
    free(resolved);
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  free(resolved);
  mbt_fs_clear_error(host);
  mbt_set_i32_result(results, nresults, 0);
  return NULL;
}

static wasm_trap_t *mbt_fs_read_dir(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  mbt_fs_host_t *host = (mbt_fs_host_t *)env;
  if (args == NULL || nargs < 1) {
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  const mbt_string_t *path_str =
    (const mbt_string_t *)mbt_externref_data(context, &args[0]);
  if (path_str == NULL) {
    mbt_fs_set_error(host, "fs: invalid path");
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  char *path_utf8 = mbt_string_to_utf8(path_str);
  char *resolved = mbt_fs_resolve_path(host, path_utf8);
  free(path_utf8);
  if (resolved == NULL) {
    mbt_fs_set_error(host, "fs: path resolve failed");
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  DIR *dir = opendir(resolved);
  if (dir == NULL) {
    mbt_fs_set_errno(host, "fs: opendir failed");
    free(resolved);
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  size_t cap = 16;
  size_t len = 0;
  char **entries = (char **)calloc(cap, sizeof(char *));
  if (entries == NULL) {
    closedir(dir);
    free(resolved);
    mbt_fs_set_error(host, "fs: alloc failed");
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  struct dirent *entry = NULL;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }
    if (len + 1 > cap) {
      size_t next_cap = cap * 2;
      char **next = (char **)realloc(entries, next_cap * sizeof(char *));
      if (next == NULL) {
        mbt_fs_set_error(host, "fs: alloc failed");
        for (size_t i = 0; i < len; i++) {
          free(entries[i]);
        }
        free(entries);
        closedir(dir);
        free(resolved);
        mbt_set_i32_result(results, nresults, -1);
        return NULL;
      }
      entries = next;
      cap = next_cap;
    }
    entries[len] = strdup(entry->d_name);
    if (entries[len] == NULL) {
      mbt_fs_set_error(host, "fs: alloc failed");
      for (size_t i = 0; i < len; i++) {
        free(entries[i]);
      }
      free(entries);
      closedir(dir);
      free(resolved);
      mbt_set_i32_result(results, nresults, -1);
      return NULL;
    }
    len += 1;
  }
  closedir(dir);
  free(resolved);
  mbt_fs_clear_dir(host);
  host->last_dir_entries = entries;
  host->last_dir_len = len;
  mbt_fs_clear_error(host);
  mbt_set_i32_result(results, nresults, 0);
  return NULL;
}

static wasm_trap_t *mbt_fs_is_file(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  mbt_fs_host_t *host = (mbt_fs_host_t *)env;
  if (args == NULL || nargs < 1) {
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  const mbt_string_t *path_str =
    (const mbt_string_t *)mbt_externref_data(context, &args[0]);
  if (path_str == NULL) {
    mbt_fs_set_error(host, "fs: invalid path");
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  char *path_utf8 = mbt_string_to_utf8(path_str);
  char *resolved = mbt_fs_resolve_path(host, path_utf8);
  free(path_utf8);
  if (resolved == NULL) {
    mbt_fs_set_error(host, "fs: path resolve failed");
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  struct stat st;
  if (stat(resolved, &st) != 0) {
    mbt_fs_set_errno(host, "fs: stat failed");
    free(resolved);
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  free(resolved);
  mbt_fs_clear_error(host);
  mbt_set_i32_result(results, nresults, S_ISREG(st.st_mode) ? 1 : 0);
  return NULL;
}

static wasm_trap_t *mbt_fs_is_dir(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  mbt_fs_host_t *host = (mbt_fs_host_t *)env;
  if (args == NULL || nargs < 1) {
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  const mbt_string_t *path_str =
    (const mbt_string_t *)mbt_externref_data(context, &args[0]);
  if (path_str == NULL) {
    mbt_fs_set_error(host, "fs: invalid path");
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  char *path_utf8 = mbt_string_to_utf8(path_str);
  char *resolved = mbt_fs_resolve_path(host, path_utf8);
  free(path_utf8);
  if (resolved == NULL) {
    mbt_fs_set_error(host, "fs: path resolve failed");
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  struct stat st;
  if (stat(resolved, &st) != 0) {
    mbt_fs_set_errno(host, "fs: stat failed");
    free(resolved);
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  free(resolved);
  mbt_fs_clear_error(host);
  mbt_set_i32_result(results, nresults, S_ISDIR(st.st_mode) ? 1 : 0);
  return NULL;
}

static wasm_trap_t *mbt_fs_remove_file(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  mbt_fs_host_t *host = (mbt_fs_host_t *)env;
  if (args == NULL || nargs < 1) {
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  const mbt_string_t *path_str =
    (const mbt_string_t *)mbt_externref_data(context, &args[0]);
  if (path_str == NULL) {
    mbt_fs_set_error(host, "fs: invalid path");
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  char *path_utf8 = mbt_string_to_utf8(path_str);
  char *resolved = mbt_fs_resolve_path(host, path_utf8);
  free(path_utf8);
  if (resolved == NULL) {
    mbt_fs_set_error(host, "fs: path resolve failed");
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  int res = remove(resolved);
  if (res != 0) {
    mbt_fs_set_errno(host, "fs: remove failed");
    free(resolved);
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  free(resolved);
  mbt_fs_clear_error(host);
  mbt_set_i32_result(results, nresults, 0);
  return NULL;
}

static wasm_trap_t *mbt_fs_remove_dir(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  mbt_fs_host_t *host = (mbt_fs_host_t *)env;
  if (args == NULL || nargs < 1) {
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  const mbt_string_t *path_str =
    (const mbt_string_t *)mbt_externref_data(context, &args[0]);
  if (path_str == NULL) {
    mbt_fs_set_error(host, "fs: invalid path");
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  char *path_utf8 = mbt_string_to_utf8(path_str);
  char *resolved = mbt_fs_resolve_path(host, path_utf8);
  free(path_utf8);
  if (resolved == NULL) {
    mbt_fs_set_error(host, "fs: path resolve failed");
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  int res = rmdir(resolved);
  if (res != 0) {
    mbt_fs_set_errno(host, "fs: rmdir failed");
    free(resolved);
    mbt_set_i32_result(results, nresults, -1);
    return NULL;
  }
  free(resolved);
  mbt_fs_clear_error(host);
  mbt_set_i32_result(results, nresults, 0);
  return NULL;
}

static wasm_trap_t *mbt_fs_args_get(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)args;
  (void)nargs;
  mbt_fs_host_t *host = (mbt_fs_host_t *)env;
  size_t len = 0;
  char **items = NULL;
  if (host != NULL && host->runtime != NULL && host->runtime->wasi_argc > 0) {
    len = host->runtime->wasi_argc;
    items = (char **)calloc(len, sizeof(char *));
    if (items != NULL) {
      for (size_t i = 0; i < len; i++) {
        items[i] = strdup(host->runtime->wasi_argv[i]);
        if (items[i] == NULL) {
          for (size_t j = 0; j < i; j++) {
            free(items[j]);
          }
          free(items);
          items = NULL;
          len = 0;
          break;
        }
      }
    } else {
      len = 0;
    }
  }
  mbt_string_array_t *arr = mbt_string_array_new(items, len);
  if (arr == NULL) {
    if (items != NULL) {
      for (size_t i = 0; i < len; i++) {
        free(items[i]);
      }
      free(items);
    }
    arr = mbt_string_array_new(NULL, 0);
  }
  mbt_set_externref_result(caller, results, nresults, arr, mbt_string_array_free);
  return NULL;
}

static wasm_trap_t *mbt_fs_current_dir(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)env;
  (void)args;
  (void)nargs;
  char buf[PATH_MAX];
  const char *dir = getcwd(buf, sizeof(buf)) != NULL ? buf : "";
  mbt_string_t *str = mbt_string_from_utf8(dir);
  if (str == NULL) {
    str = mbt_string_new(NULL, 0);
  }
  mbt_set_externref_result(caller, results, nresults, str, mbt_string_free);
  return NULL;
}

static wasm_trap_t *mbt_fs_get_env_var(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)env;
  if (args == NULL || nargs < 1) {
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  const mbt_string_t *key_str =
    (const mbt_string_t *)mbt_externref_data(context, &args[0]);
  char *key = mbt_string_to_utf8(key_str);
  const char *val = key != NULL ? getenv(key) : NULL;
  mbt_string_t *str = mbt_string_from_utf8(val != NULL ? val : "");
  free(key);
  if (str == NULL) {
    str = mbt_string_new(NULL, 0);
  }
  mbt_set_externref_result(caller, results, nresults, str, mbt_string_free);
  return NULL;
}

static wasm_trap_t *mbt_fs_get_env_var_exists(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)env;
  if (args == NULL || nargs < 1) {
    mbt_set_i32_result(results, nresults, 0);
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  const mbt_string_t *key_str =
    (const mbt_string_t *)mbt_externref_data(context, &args[0]);
  char *key = mbt_string_to_utf8(key_str);
  int ok = 0;
  if (key != NULL) {
    ok = getenv(key) != NULL ? 1 : 0;
  }
  free(key);
  mbt_set_i32_result(results, nresults, ok);
  return NULL;
}

static wasm_trap_t *mbt_fs_get_env_vars(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)env;
  (void)args;
  (void)nargs;
  extern char **environ;
  size_t count = 0;
  if (environ != NULL) {
    while (environ[count] != NULL) {
      count++;
    }
  }
  char **items = NULL;
  size_t len = 0;
  if (count > 0) {
    items = (char **)calloc(count * 2, sizeof(char *));
    if (items != NULL) {
      for (size_t i = 0; i < count; i++) {
        char *entry = environ[i];
        char *eq = strchr(entry, '=');
        if (eq == NULL) {
          items[len++] = strdup(entry);
          items[len++] = strdup("");
        } else {
          size_t key_len = (size_t)(eq - entry);
          char *key = (char *)malloc(key_len + 1);
          if (key != NULL) {
            memcpy(key, entry, key_len);
            key[key_len] = '\0';
          }
          char *val = strdup(eq + 1);
          items[len++] = key != NULL ? key : strdup("");
          items[len++] = val != NULL ? val : strdup("");
        }
      }
    }
  }
  mbt_string_array_t *arr = mbt_string_array_new(items, len);
  if (arr == NULL) {
    if (items != NULL) {
      for (size_t i = 0; i < len; i++) {
        free(items[i]);
      }
      free(items);
    }
    arr = mbt_string_array_new(NULL, 0);
  }
  mbt_set_externref_result(caller, results, nresults, arr, mbt_string_array_free);
  return NULL;
}

static wasm_trap_t *mbt_fs_set_env_var(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)env;
  (void)results;
  (void)nresults;
  if (args == NULL || nargs < 2) {
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  const mbt_string_t *key_str =
    (const mbt_string_t *)mbt_externref_data(context, &args[0]);
  const mbt_string_t *val_str =
    (const mbt_string_t *)mbt_externref_data(context, &args[1]);
  char *key = mbt_string_to_utf8(key_str);
  char *val = mbt_string_to_utf8(val_str);
  if (key != NULL && val != NULL) {
    setenv(key, val, 1);
  }
  free(key);
  free(val);
  return NULL;
}

static wasm_trap_t *mbt_fs_unset_env_var(
  void *env,
  wasmtime_caller_t *caller,
  const wasmtime_val_t *args,
  size_t nargs,
  wasmtime_val_t *results,
  size_t nresults
) {
  (void)env;
  (void)results;
  (void)nresults;
  if (args == NULL || nargs < 1) {
    return NULL;
  }
  wasmtime_context_t *context = wasmtime_caller_context(caller);
  const mbt_string_t *key_str =
    (const mbt_string_t *)mbt_externref_data(context, &args[0]);
  char *key = mbt_string_to_utf8(key_str);
  if (key != NULL) {
    unsetenv(key);
  }
  free(key);
  return NULL;
}

static wasmtime_error_t *mbt_define_fs_func(
  wasmtime_linker_t *linker,
  wasmtime_context_t *context,
  const char *module,
  size_t module_len,
  const char *name,
  const uint8_t *params,
  int32_t nparams,
  const uint8_t *results,
  int32_t nresults,
  wasmtime_func_callback_t cb,
  void *env
) {
  wasm_functype_t *ty = wasmtime_functype_new_from_kinds(params, nparams, results, nresults);
  if (ty == NULL) {
    return wasmtime_error_new("fs: functype_new failed");
  }
  wasmtime_func_t func;
  wasmtime_func_new(context, ty, cb, env, NULL, &func);
  wasm_functype_delete(ty);
  wasmtime_extern_t item;
  item.kind = WASMTIME_EXTERN_FUNC;
  item.of.func = func;
  return wasmtime_linker_define(
    linker,
    context,
    module,
    module_len,
    name,
    strlen(name),
    &item
  );
}

static wasmtime_error_t *mbt_define_moonbit_fs_unstable(
  wasmtime_linker_t *linker,
  wasmtime_context_t *context,
  mbt_fs_host_t *host
) {
  if (linker == NULL || context == NULL) {
    return wasmtime_error_new("fs: linker/context missing");
  }
  const char *module = "__moonbit_fs_unstable";
  size_t module_len = strlen(module);
  uint8_t params_ref[1] = { WASM_EXTERNREF };
  uint8_t params_ref_ref[2] = { WASM_EXTERNREF, WASM_EXTERNREF };
  uint8_t params_ref_i32[2] = { WASM_EXTERNREF, WASMTIME_I32 };
  uint8_t results_ref[1] = { WASM_EXTERNREF };
  uint8_t results_i32[1] = { WASMTIME_I32 };
  wasmtime_error_t *err = NULL;

#define DEFINE_FS(name, params, nparams, results, nresults, cb) \
  do { \
    err = mbt_define_fs_func( \
      linker, context, module, module_len, name, params, nparams, results, nresults, cb, host \
    ); \
    if (err != NULL) { \
      return err; \
    } \
  } while (0)

  DEFINE_FS("begin_create_string", NULL, 0, results_ref, 1, mbt_fs_begin_create_string);
  DEFINE_FS("string_append_char", params_ref_i32, 2, NULL, 0, mbt_fs_string_append_char);
  DEFINE_FS("finish_create_string", params_ref, 1, results_ref, 1, mbt_fs_finish_create_string);
  DEFINE_FS("begin_read_string", params_ref, 1, results_ref, 1, mbt_fs_begin_read_string);
  DEFINE_FS("string_read_char", params_ref, 1, results_i32, 1, mbt_fs_string_read_char);
  DEFINE_FS("finish_read_string", params_ref, 1, NULL, 0, mbt_fs_finish_read_string);

  DEFINE_FS("begin_create_byte_array", NULL, 0, results_ref, 1, mbt_fs_begin_create_byte_array);
  DEFINE_FS("byte_array_append_byte", params_ref_i32, 2, NULL, 0, mbt_fs_byte_array_append_byte);
  DEFINE_FS("finish_create_byte_array", params_ref, 1, results_ref, 1, mbt_fs_finish_create_byte_array);
  DEFINE_FS("begin_read_byte_array", params_ref, 1, results_ref, 1, mbt_fs_begin_read_byte_array);
  DEFINE_FS("byte_array_read_byte", params_ref, 1, results_i32, 1, mbt_fs_byte_array_read_byte);
  DEFINE_FS("finish_read_byte_array", params_ref, 1, NULL, 0, mbt_fs_finish_read_byte_array);

  DEFINE_FS("begin_read_string_array", params_ref, 1, results_ref, 1, mbt_fs_begin_read_string_array);
  DEFINE_FS("string_array_read_string", params_ref, 1, results_ref, 1, mbt_fs_string_array_read_string);
  DEFINE_FS("finish_read_string_array", params_ref, 1, NULL, 0, mbt_fs_finish_read_string_array);

  DEFINE_FS("get_error_message", NULL, 0, results_ref, 1, mbt_fs_get_error_message);
  DEFINE_FS("get_file_content", NULL, 0, results_ref, 1, mbt_fs_get_file_content);
  DEFINE_FS("get_dir_files", NULL, 0, results_ref, 1, mbt_fs_get_dir_files);

  DEFINE_FS("read_file_to_bytes_new", params_ref, 1, results_i32, 1, mbt_fs_read_file_to_bytes);
  DEFINE_FS("write_bytes_to_file_new", params_ref_ref, 2, results_i32, 1, mbt_fs_write_bytes_to_file);
  DEFINE_FS("path_exists", params_ref, 1, results_i32, 1, mbt_fs_path_exists);
  DEFINE_FS("create_dir_new", params_ref, 1, results_i32, 1, mbt_fs_create_dir);
  DEFINE_FS("read_dir_new", params_ref, 1, results_i32, 1, mbt_fs_read_dir);
  DEFINE_FS("is_file_new", params_ref, 1, results_i32, 1, mbt_fs_is_file);
  DEFINE_FS("is_dir_new", params_ref, 1, results_i32, 1, mbt_fs_is_dir);
  DEFINE_FS("remove_file_new", params_ref, 1, results_i32, 1, mbt_fs_remove_file);
  DEFINE_FS("remove_dir_new", params_ref, 1, results_i32, 1, mbt_fs_remove_dir);

  DEFINE_FS("args_get", NULL, 0, results_ref, 1, mbt_fs_args_get);
  DEFINE_FS("current_dir", NULL, 0, results_ref, 1, mbt_fs_current_dir);
  DEFINE_FS("get_env_var", params_ref, 1, results_ref, 1, mbt_fs_get_env_var);
  DEFINE_FS("get_env_var_exists", params_ref, 1, results_i32, 1, mbt_fs_get_env_var_exists);
  DEFINE_FS("get_env_vars", NULL, 0, results_ref, 1, mbt_fs_get_env_vars);
  DEFINE_FS("set_env_var", params_ref_ref, 2, NULL, 0, mbt_fs_set_env_var);
  DEFINE_FS("unset_env_var", params_ref, 1, NULL, 0, mbt_fs_unset_env_var);

#undef DEFINE_FS

  return NULL;
}

static void wasmtime_thread_runtime_clear_argv(wasmtime_thread_runtime_t *runtime) {
  if (runtime == NULL || runtime->wasi_argv == NULL) {
    return;
  }
  for (size_t i = 0; i < runtime->wasi_argc; i++) {
    free(runtime->wasi_argv[i]);
  }
  free(runtime->wasi_argv);
  runtime->wasi_argv = NULL;
  runtime->wasi_argc = 0;
}

static void wasmtime_thread_runtime_clear_preopen(wasmtime_thread_runtime_t *runtime) {
  if (runtime == NULL) {
    return;
  }
  if (runtime->wasi_preopen_host != NULL) {
    free(runtime->wasi_preopen_host);
    runtime->wasi_preopen_host = NULL;
  }
  if (runtime->wasi_preopen_guest != NULL) {
    free(runtime->wasi_preopen_guest);
    runtime->wasi_preopen_guest = NULL;
  }
}

static void wasmtime_thread_task_set_error(
  wasmtime_thread_task_t *task,
  wasmtime_error_t *err,
  const char *msg
) {
  if (task == NULL || task->error != NULL) {
    if (err != NULL) {
      wasmtime_error_delete(err);
    }
    return;
  }
  if (err != NULL) {
    task->error = err;
    return;
  }
  if (msg != NULL) {
    task->error = wasmtime_error_new(msg);
  }
}

static bool wasmtime_thread_task_mark_collected(wasmtime_thread_task_t *task) {
  bool expected = false;
  return atomic_compare_exchange_strong(&task->collected, &expected, true);
}

static void wasmtime_thread_task_cleanup(wasmtime_thread_task_t *task) {
  if (task == NULL) {
    return;
  }
  if (task->module != NULL) {
    wasmtime_module_delete(task->module);
  }
  if (task->args != NULL) {
    free(task->args);
  }
  if (task->func_name != NULL) {
    free(task->func_name);
  }
  if (task->error != NULL) {
    wasmtime_error_delete(task->error);
    task->error = NULL;
  }
  free(task);
}

static void wasmtime_thread_task_mark_done(wasmtime_thread_task_t *task) {
  if (task != NULL) {
    atomic_store_explicit(&task->done, true, memory_order_release);
  }
}

static void *wasmtime_thread_main(void *arg) {
  wasmtime_thread_task_t *task = (wasmtime_thread_task_t *)arg;
  mbt_fs_host_t *fs_host = NULL;
  wasmtime_error_t *err = NULL;
  if (task == NULL || task->runtime == NULL || task->runtime->engine == NULL) {
    wasmtime_thread_task_set_error(task, NULL, "thread: runtime invalid");
    goto done;
  }
  if (task->module == NULL) {
    wasmtime_thread_task_set_error(task, NULL, "thread: module missing");
    goto done;
  }
  wasmtime_store_t *store = wasmtime_store_new(task->runtime->engine, NULL, NULL);
  if (store == NULL) {
    wasmtime_thread_task_set_error(task, NULL, "thread: store_new failed");
    goto done;
  }
  wasmtime_context_t *context = wasmtime_store_context(store);
  wasmtime_linker_t *linker = wasmtime_linker_new(task->runtime->engine);
  if (linker == NULL) {
    wasmtime_store_delete(store);
    wasmtime_thread_task_set_error(task, NULL, "thread: linker_new failed");
    goto done;
  }
  fs_host = mbt_fs_host_new(task->runtime);
  if (fs_host == NULL) {
    wasmtime_linker_delete(linker);
    wasmtime_store_delete(store);
    wasmtime_thread_task_set_error(task, NULL, "thread: fs host alloc failed");
    goto done;
  }
  err = mbt_define_moonbit_fs_unstable(linker, context, fs_host);
  if (err != NULL) {
    wasmtime_thread_task_set_error(task, err, NULL);
    wasmtime_linker_delete(linker);
    wasmtime_store_delete(store);
    goto done;
  }
  wasmtime_sharedmemory_t *shared = wasmtime_sharedmemory_clone(task->runtime->shared);
  if (shared == NULL) {
    wasmtime_linker_delete(linker);
    wasmtime_store_delete(store);
    wasmtime_thread_task_set_error(task, NULL, "thread: sharedmemory_clone failed");
    goto done;
  }
  wasmtime_extern_t mem_extern;
  mem_extern.kind = WASMTIME_EXTERN_SHAREDMEMORY;
  mem_extern.of.sharedmemory = shared;
  err = wasmtime_linker_define(
    linker,
    context,
    "env",
    3,
    "mem",
    3,
    &mem_extern
  );
  if (err != NULL) {
    wasmtime_thread_task_set_error(task, err, NULL);
    wasmtime_sharedmemory_delete(shared);
    wasmtime_linker_delete(linker);
    wasmtime_store_delete(store);
    goto done;
  }
  wasi_config_t *wasi_config = NULL;
  if (task->runtime->wasi_preopen_host != NULL || task->runtime->wasi_inherit_stdio ||
      task->runtime->wasi_inherit_argv || task->runtime->wasi_argc > 0) {
    wasi_config = wasi_config_new();
    if (wasi_config == NULL) {
      wasmtime_thread_task_set_error(task, NULL, "thread: wasi_config_new failed");
      wasmtime_sharedmemory_delete(shared);
      wasmtime_linker_delete(linker);
      wasmtime_store_delete(store);
      goto done;
    }
    if (task->runtime->wasi_inherit_stdio) {
      wasi_config_inherit_stdin(wasi_config);
      wasi_config_inherit_stdout(wasi_config);
      wasi_config_inherit_stderr(wasi_config);
    }
    if (task->runtime->wasi_inherit_argv) {
      wasi_config_inherit_argv(wasi_config);
    } else if (task->runtime->wasi_argc > 0) {
      if (!wasi_config_set_argv(
            wasi_config,
            task->runtime->wasi_argc,
            (const char **)task->runtime->wasi_argv
          )) {
        wasmtime_thread_task_set_error(task, NULL, "thread: wasi_config_set_argv failed");
        wasi_config_delete(wasi_config);
        wasmtime_sharedmemory_delete(shared);
        wasmtime_linker_delete(linker);
        wasmtime_store_delete(store);
        goto done;
      }
    }
    if (task->runtime->wasi_preopen_host != NULL) {
      const char *guest_path =
        task->runtime->wasi_preopen_guest != NULL ? task->runtime->wasi_preopen_guest : ".";
      if (!wasi_config_preopen_dir(
            wasi_config,
            task->runtime->wasi_preopen_host,
            guest_path,
            (size_t)task->runtime->wasi_dir_perms,
            (size_t)task->runtime->wasi_file_perms
          )) {
        wasmtime_thread_task_set_error(task, NULL, "thread: wasi_config_preopen_dir failed");
        wasi_config_delete(wasi_config);
        wasmtime_sharedmemory_delete(shared);
        wasmtime_linker_delete(linker);
        wasmtime_store_delete(store);
        goto done;
      }
    }
    err = wasmtime_context_set_wasi(context, wasi_config);
    if (err != NULL) {
      wasmtime_thread_task_set_error(task, err, NULL);
      wasmtime_sharedmemory_delete(shared);
      wasmtime_linker_delete(linker);
      wasmtime_store_delete(store);
      goto done;
    }
    wasi_config = NULL;
    err = wasmtime_linker_define_wasi(linker);
    if (err != NULL) {
      wasmtime_thread_task_set_error(task, err, NULL);
      wasmtime_sharedmemory_delete(shared);
      wasmtime_linker_delete(linker);
      wasmtime_store_delete(store);
      goto done;
    }
  }
  wasmtime_instance_t instance;
  wasm_trap_t *trap = NULL;
  err = wasmtime_linker_instantiate(linker, context, task->module, &instance, &trap);
  if (trap != NULL) {
    wasm_trap_delete(trap);
  }
  if (err != NULL || trap != NULL) {
    if (err != NULL) {
      wasmtime_thread_task_set_error(task, err, NULL);
    } else {
      wasmtime_thread_task_set_error(task, NULL, "thread: instantiate trap");
    }
    wasmtime_sharedmemory_delete(shared);
    wasmtime_linker_delete(linker);
    wasmtime_store_delete(store);
    goto done;
  }
  wasmtime_extern_t item;
  if (!wasmtime_instance_export_get(
        context,
        &instance,
        task->func_name,
        task->func_name_len,
        &item
      )) {
    wasmtime_thread_task_set_error(task, NULL, "thread: export_get failed");
    wasmtime_sharedmemory_delete(shared);
    wasmtime_linker_delete(linker);
    wasmtime_store_delete(store);
    goto done;
  }
  if (item.kind != WASMTIME_EXTERN_FUNC) {
    wasmtime_extern_delete(&item);
    wasmtime_thread_task_set_error(task, NULL, "thread: export kind mismatch");
    wasmtime_sharedmemory_delete(shared);
    wasmtime_linker_delete(linker);
    wasmtime_store_delete(store);
    goto done;
  }
  wasmtime_func_t func = item.of.func;
  size_t repeat = task->repeat == 0 ? 1 : task->repeat;
  for (size_t i = 0; i < repeat; i++) {
    trap = NULL;
    err = wasmtime_func_call(
      context,
      &func,
      task->args,
      task->nargs,
      NULL,
      0,
      &trap
    );
    if (err != NULL) {
      int status = 0;
      if (wasmtime_error_exit_status(err, &status)) {
        if (status == 0) {
          wasmtime_error_delete(err);
          err = NULL;
        } else {
          char buf[64];
          snprintf(buf, sizeof(buf), "thread: wasi proc_exit(%d)", status);
          wasmtime_error_delete(err);
          err = wasmtime_error_new(buf);
        }
      }
    }
    if (trap != NULL) {
      wasm_trap_delete(trap);
      trap = NULL;
    }
    if (err != NULL || trap != NULL) {
      break;
    }
  }
  wasmtime_extern_delete(&item);
  if (err != NULL || trap != NULL) {
    if (err != NULL) {
      wasmtime_thread_task_set_error(task, err, NULL);
    } else {
      wasmtime_thread_task_set_error(task, NULL, "thread: call trap");
    }
    wasmtime_sharedmemory_delete(shared);
    wasmtime_linker_delete(linker);
    wasmtime_store_delete(store);
    goto done;
  }
  wasmtime_sharedmemory_delete(shared);
  wasmtime_linker_delete(linker);
  wasmtime_store_delete(store);
done:
  if (fs_host != NULL) {
    mbt_fs_host_free(fs_host);
  }
  wasmtime_thread_task_mark_done(task);
  if (atomic_load_explicit(&task->detached, memory_order_acquire)) {
    if (wasmtime_thread_task_mark_collected(task)) {
      wasmtime_thread_task_cleanup(task);
    }
  }
  return NULL;
}

#endif

uint64_t wasmtime_thread_runtime_new(uint64_t pages, uint8_t *error_out) {
  wasmtime_bench_error_clear(error_out);
#if defined(_WIN32)
  (void)pages;
  wasmtime_bench_error_message(error_out, "thread: runtime not supported on windows");
  return 0;
#else
  if (pages == 0) {
    pages = 1;
  }
  wasm_config_t *config = wasm_config_new();
  if (config == NULL) {
    wasmtime_bench_error_message(error_out, "thread: config_new failed");
    return 0;
  }
  wasmtime_config_wasm_threads_set(config, true);
  wasmtime_config_shared_memory_set(config, true);
  wasmtime_config_wasm_gc_set(config, true);
  wasmtime_config_wasm_reference_types_set(config, true);
  wasmtime_config_wasm_function_references_set(config, true);
  wasm_engine_t *engine = wasm_engine_new_with_config(config);
  if (engine == NULL) {
    wasm_config_delete(config);
    wasmtime_bench_error_message(error_out, "thread: engine_new_with_config failed");
    return 0;
  }
  wasm_memorytype_t *mem_ty = NULL;
  wasmtime_error_t *err = wasmtime_memorytype_new(
    pages,
    true,
    pages,
    false,
    true,
    16,
    &mem_ty
  );
  if (err != NULL || mem_ty == NULL) {
    if (err != NULL) {
      wasmtime_bench_error_take(error_out, err);
    } else {
      wasmtime_bench_error_message(error_out, "thread: memorytype_new failed");
    }
    wasm_engine_delete(engine);
    return 0;
  }
  wasmtime_sharedmemory_t *shared = NULL;
  err = wasmtime_sharedmemory_new(engine, mem_ty, &shared);
  wasm_memorytype_delete(mem_ty);
  if (err != NULL || shared == NULL) {
    if (err != NULL) {
      wasmtime_bench_error_take(error_out, err);
    } else {
      wasmtime_bench_error_message(error_out, "thread: sharedmemory_new failed");
    }
    wasm_engine_delete(engine);
    return 0;
  }
  wasmtime_thread_runtime_t *runtime =
    (wasmtime_thread_runtime_t *)calloc(1, sizeof(wasmtime_thread_runtime_t));
  if (runtime == NULL) {
    wasmtime_bench_error_message(error_out, "thread: runtime alloc failed");
    wasmtime_sharedmemory_delete(shared);
    wasm_engine_delete(engine);
    return 0;
  }
  runtime->engine = engine;
  runtime->shared = shared;
  runtime->pages = pages;
  return (uint64_t)(uintptr_t)runtime;
#endif
}

void wasmtime_thread_runtime_delete(uint64_t handle) {
#if defined(_WIN32)
  (void)handle;
#else
  if (handle == 0) {
    return;
  }
  wasmtime_thread_runtime_t *runtime =
    (wasmtime_thread_runtime_t *)(uintptr_t)handle;
  wasmtime_thread_runtime_clear_argv(runtime);
  wasmtime_thread_runtime_clear_preopen(runtime);
  if (runtime->shared != NULL) {
    wasmtime_sharedmemory_delete(runtime->shared);
  }
  if (runtime->engine != NULL) {
    wasm_engine_delete(runtime->engine);
  }
  free(runtime);
#endif
}

bool wasmtime_thread_runtime_wasi_preopen_dir(
  uint64_t runtime_handle,
  const uint8_t *host_path,
  int32_t host_len,
  const uint8_t *guest_path,
  int32_t guest_len,
  int32_t dir_perms,
  int32_t file_perms,
  uint8_t *error_out
) {
  wasmtime_bench_error_clear(error_out);
#if defined(_WIN32)
  (void)runtime_handle;
  (void)host_path;
  (void)host_len;
  (void)guest_path;
  (void)guest_len;
  (void)dir_perms;
  (void)file_perms;
  wasmtime_bench_error_message(error_out, "thread: wasi not supported on windows");
  return false;
#else
  if (runtime_handle == 0) {
    wasmtime_bench_error_message(error_out, "thread: runtime handle invalid");
    return false;
  }
  if (host_path == NULL || host_len <= 0) {
    wasmtime_bench_error_message(error_out, "thread: wasi host path invalid");
    return false;
  }
  wasmtime_thread_runtime_t *runtime =
    (wasmtime_thread_runtime_t *)(uintptr_t)runtime_handle;
  char *host_cstr = wasmtime_mbt_copy_cstr(host_path, host_len);
  if (host_cstr == NULL) {
    wasmtime_bench_error_message(error_out, "thread: wasi host path alloc failed");
    return false;
  }
  char *guest_cstr = NULL;
  if (guest_path != NULL && guest_len > 0) {
    guest_cstr = wasmtime_mbt_copy_cstr(guest_path, guest_len);
  }
  if (guest_cstr == NULL) {
    guest_cstr = wasmtime_mbt_copy_cstr((const uint8_t *)".", 1);
  }
  if (guest_cstr == NULL) {
    free(host_cstr);
    wasmtime_bench_error_message(error_out, "thread: wasi guest path alloc failed");
    return false;
  }
  wasmtime_thread_runtime_clear_preopen(runtime);
  runtime->wasi_preopen_host = host_cstr;
  runtime->wasi_preopen_guest = guest_cstr;
  runtime->wasi_dir_perms = dir_perms;
  runtime->wasi_file_perms = file_perms;
  return true;
#endif
}

bool wasmtime_thread_runtime_wasi_set_argv_bytes(
  uint64_t runtime_handle,
  const uint8_t *argv_bytes,
  int32_t argv_len,
  uint8_t *error_out
) {
  wasmtime_bench_error_clear(error_out);
#if defined(_WIN32)
  (void)runtime_handle;
  (void)argv_bytes;
  (void)argv_len;
  wasmtime_bench_error_message(error_out, "thread: wasi not supported on windows");
  return false;
#else
  if (runtime_handle == 0) {
    wasmtime_bench_error_message(error_out, "thread: runtime handle invalid");
    return false;
  }
  wasmtime_thread_runtime_t *runtime =
    (wasmtime_thread_runtime_t *)(uintptr_t)runtime_handle;
  wasmtime_thread_runtime_clear_argv(runtime);
  runtime->wasi_inherit_argv = false;
  if (argv_bytes == NULL || argv_len <= 0) {
    return true;
  }
  size_t len = (size_t)argv_len;
  size_t count = 0;
  size_t i = 0;
  while (i < len) {
    size_t start = i;
    while (i < len && argv_bytes[i] != 0) {
      i++;
    }
    size_t seg_len = i - start;
    if (seg_len > 0) {
      count++;
    }
    if (i < len && argv_bytes[i] == 0) {
      i++;
    }
  }
  if (count == 0) {
    return true;
  }
  char **argv = (char **)calloc(count, sizeof(char *));
  if (argv == NULL) {
    wasmtime_bench_error_message(error_out, "thread: wasi argv alloc failed");
    return false;
  }
  size_t idx = 0;
  i = 0;
  while (i < len && idx < count) {
    size_t start = i;
    while (i < len && argv_bytes[i] != 0) {
      i++;
    }
    size_t seg_len = i - start;
    if (seg_len > 0) {
      char *buf = (char *)malloc(seg_len + 1);
      if (buf == NULL) {
        for (size_t j = 0; j < idx; j++) {
          free(argv[j]);
        }
        free(argv);
        wasmtime_bench_error_message(error_out, "thread: wasi argv alloc failed");
        return false;
      }
      memcpy(buf, argv_bytes + start, seg_len);
      buf[seg_len] = '\0';
      argv[idx] = buf;
      idx++;
    }
    if (i < len && argv_bytes[i] == 0) {
      i++;
    }
  }
  runtime->wasi_argv = argv;
  runtime->wasi_argc = idx;
  return true;
#endif
}

bool wasmtime_thread_runtime_wasi_inherit_argv(
  uint64_t runtime_handle,
  uint8_t *error_out
) {
  wasmtime_bench_error_clear(error_out);
#if defined(_WIN32)
  (void)runtime_handle;
  wasmtime_bench_error_message(error_out, "thread: wasi not supported on windows");
  return false;
#else
  if (runtime_handle == 0) {
    wasmtime_bench_error_message(error_out, "thread: runtime handle invalid");
    return false;
  }
  wasmtime_thread_runtime_t *runtime =
    (wasmtime_thread_runtime_t *)(uintptr_t)runtime_handle;
  wasmtime_thread_runtime_clear_argv(runtime);
  runtime->wasi_inherit_argv = true;
  return true;
#endif
}

bool wasmtime_thread_runtime_wasi_inherit_stdio(
  uint64_t runtime_handle,
  uint8_t *error_out
) {
  wasmtime_bench_error_clear(error_out);
#if defined(_WIN32)
  (void)runtime_handle;
  wasmtime_bench_error_message(error_out, "thread: wasi not supported on windows");
  return false;
#else
  if (runtime_handle == 0) {
    wasmtime_bench_error_message(error_out, "thread: runtime handle invalid");
    return false;
  }
  wasmtime_thread_runtime_t *runtime =
    (wasmtime_thread_runtime_t *)(uintptr_t)runtime_handle;
  runtime->wasi_inherit_stdio = true;
  return true;
#endif
}

uint64_t wasmtime_thread_runtime_spawn_wat(
  uint64_t runtime_handle,
  const uint8_t *wat,
  int32_t wat_len,
  const uint8_t *func_name,
  int32_t func_name_len,
  const uint8_t *args,
  int32_t args_len,
  uint8_t *error_out
) {
  wasmtime_bench_error_clear(error_out);
#if defined(_WIN32)
  (void)runtime_handle;
  (void)wat;
  (void)wat_len;
  (void)func_name;
  (void)func_name_len;
  (void)args;
  (void)args_len;
  wasmtime_bench_error_message(error_out, "thread: spawn not supported on windows");
  return 0;
#else
  if (runtime_handle == 0) {
    wasmtime_bench_error_message(error_out, "thread: runtime handle invalid");
    return 0;
  }
  if (wat == NULL || wat_len <= 0) {
    wasmtime_bench_error_message(error_out, "thread: wat input invalid");
    return 0;
  }
  if (func_name == NULL || func_name_len <= 0) {
    wasmtime_bench_error_message(error_out, "thread: func name invalid");
    return 0;
  }
  if (args_len < 0) {
    wasmtime_bench_error_message(error_out, "thread: args length invalid");
    return 0;
  }
  size_t val_size = sizeof(wasmtime_val_t);
  if (val_size == 0) {
    wasmtime_bench_error_message(error_out, "thread: val size invalid");
    return 0;
  }
  if (args_len % (int32_t)val_size != 0) {
    wasmtime_bench_error_message(error_out, "thread: args length mismatch");
    return 0;
  }
  size_t nargs = (size_t)args_len / val_size;
  if (nargs > 0 && args == NULL) {
    wasmtime_bench_error_message(error_out, "thread: args missing");
    return 0;
  }
  wasmtime_thread_runtime_t *runtime =
    (wasmtime_thread_runtime_t *)(uintptr_t)runtime_handle;
  if (runtime->engine == NULL || runtime->shared == NULL) {
    wasmtime_bench_error_message(error_out, "thread: runtime not initialized");
    return 0;
  }
  wasm_byte_vec_t wasm = {0, NULL};
  wasmtime_error_t *err = wasmtime_wat2wasm((const char *)wat, (size_t)wat_len, &wasm);
  if (err != NULL) {
    wasmtime_bench_error_take(error_out, err);
    return 0;
  }
  wasmtime_module_t *module = NULL;
  err = wasmtime_module_new(runtime->engine, wasm.data, wasm.size, &module);
  wasm_byte_vec_delete(&wasm);
  if (err != NULL || module == NULL) {
    if (err != NULL) {
      wasmtime_bench_error_take(error_out, err);
    } else {
      wasmtime_bench_error_message(error_out, "thread: module_new failed");
    }
    return 0;
  }
  wasmtime_thread_task_t *task =
    (wasmtime_thread_task_t *)calloc(1, sizeof(wasmtime_thread_task_t));
  if (task == NULL) {
    wasmtime_bench_error_message(error_out, "thread: task alloc failed");
    wasmtime_module_delete(module);
    return 0;
  }
  atomic_init(&task->done, false);
  atomic_init(&task->detached, false);
  atomic_init(&task->collected, false);
  task->runtime = runtime;
  task->module = module;
  task->func_name = (char *)malloc((size_t)func_name_len);
  if (task->func_name == NULL) {
    wasmtime_bench_error_message(error_out, "thread: func name alloc failed");
    wasmtime_module_delete(module);
    free(task);
    return 0;
  }
  memcpy(task->func_name, func_name, (size_t)func_name_len);
  task->func_name_len = (size_t)func_name_len;
  task->nargs = nargs;
  task->repeat = 1;
  if (nargs > 0) {
    task->args = (wasmtime_val_t *)malloc(nargs * sizeof(wasmtime_val_t));
    if (task->args == NULL) {
      wasmtime_bench_error_message(error_out, "thread: args alloc failed");
      wasmtime_module_delete(module);
      free(task->func_name);
      free(task);
      return 0;
    }
    memcpy(task->args, args, nargs * sizeof(wasmtime_val_t));
  }
  if (pthread_create(&task->thread, NULL, wasmtime_thread_main, task) != 0) {
    wasmtime_bench_error_message(error_out, "thread: thread spawn failed");
    wasmtime_module_delete(module);
    if (task->args != NULL) {
      free(task->args);
    }
    free(task->func_name);
    free(task);
    return 0;
  }
  return (uint64_t)(uintptr_t)task;
#endif
}

moonbit_bytes_t wasmtime_thread_runtime_precompile_cwasm(
  uint64_t runtime_handle,
  const uint8_t *wasm,
  int32_t wasm_len,
  uint8_t *error_out
) {
  wasmtime_bench_error_clear(error_out);
#if defined(_WIN32)
  (void)runtime_handle;
  (void)wasm;
  (void)wasm_len;
  wasmtime_bench_error_message(error_out, "thread: precompile not supported on windows");
  return NULL;
#else
  if (runtime_handle == 0) {
    wasmtime_bench_error_message(error_out, "thread: runtime handle invalid");
    return NULL;
  }
  if (wasm == NULL || wasm_len <= 0) {
    wasmtime_bench_error_message(error_out, "thread: wasm input invalid");
    return NULL;
  }
  wasmtime_thread_runtime_t *runtime =
    (wasmtime_thread_runtime_t *)(uintptr_t)runtime_handle;
  if (runtime->engine == NULL) {
    wasmtime_bench_error_message(error_out, "thread: runtime not initialized");
    return NULL;
  }
  wasmtime_module_t *module = NULL;
  wasmtime_error_t *err =
    wasmtime_module_new(runtime->engine, wasm, (size_t)wasm_len, &module);
  if (err != NULL || module == NULL) {
    if (err != NULL) {
      wasmtime_bench_error_take(error_out, err);
    } else {
      wasmtime_bench_error_message(error_out, "thread: module_new failed");
    }
    return NULL;
  }
  wasm_byte_vec_t serialized = {0, NULL};
  err = wasmtime_module_serialize(module, &serialized);
  wasmtime_module_delete(module);
  if (err != NULL) {
    wasmtime_bench_error_take(error_out, err);
    return NULL;
  }
  if (serialized.size > INT32_MAX) {
    wasm_byte_vec_delete(&serialized);
    wasmtime_bench_error_message(error_out, "thread: cwasm too large");
    return NULL;
  }
  moonbit_bytes_t out = moonbit_make_bytes((int32_t)serialized.size, 0);
  if (serialized.size > 0 && out != NULL) {
    memcpy(out, serialized.data, serialized.size);
  }
  wasm_byte_vec_delete(&serialized);
  if (out == NULL) {
    wasmtime_bench_error_message(error_out, "thread: cwasm alloc failed");
    return NULL;
  }
  return out;
#endif
}

static uint64_t wasmtime_thread_runtime_spawn_wasm_impl(
  uint64_t runtime_handle,
  const uint8_t *wasm,
  int32_t wasm_len,
  bool serialized,
  const uint8_t *func_name,
  int32_t func_name_len,
  const uint8_t *args,
  int32_t args_len,
  size_t repeat,
  uint8_t *error_out
) {
  if (runtime_handle == 0) {
    wasmtime_bench_error_message(error_out, "thread: runtime handle invalid");
    return 0;
  }
  if (wasm == NULL || wasm_len <= 0) {
    wasmtime_bench_error_message(error_out, "thread: wasm input invalid");
    return 0;
  }
  if (func_name == NULL || func_name_len <= 0) {
    wasmtime_bench_error_message(error_out, "thread: func name invalid");
    return 0;
  }
  if (args_len < 0) {
    wasmtime_bench_error_message(error_out, "thread: args length invalid");
    return 0;
  }
  size_t val_size = sizeof(wasmtime_val_t);
  if (val_size == 0) {
    wasmtime_bench_error_message(error_out, "thread: val size invalid");
    return 0;
  }
  if (args_len % (int32_t)val_size != 0) {
    wasmtime_bench_error_message(error_out, "thread: args length mismatch");
    return 0;
  }
  size_t nargs = (size_t)args_len / val_size;
  if (nargs > 0 && args == NULL) {
    wasmtime_bench_error_message(error_out, "thread: args missing");
    return 0;
  }
  wasmtime_thread_runtime_t *runtime =
    (wasmtime_thread_runtime_t *)(uintptr_t)runtime_handle;
  if (runtime->engine == NULL || runtime->shared == NULL) {
    wasmtime_bench_error_message(error_out, "thread: runtime not initialized");
    return 0;
  }
  wasmtime_module_t *module = NULL;
  wasmtime_error_t *err = NULL;
  if (serialized) {
    err = wasmtime_module_deserialize(runtime->engine, wasm, (size_t)wasm_len, &module);
  } else {
    err = wasmtime_module_new(runtime->engine, wasm, (size_t)wasm_len, &module);
  }
  if (err != NULL || module == NULL) {
    if (err != NULL) {
      wasmtime_bench_error_take(error_out, err);
    } else {
      wasmtime_bench_error_message(error_out, "thread: module load failed");
    }
    return 0;
  }
  wasmtime_thread_task_t *task =
    (wasmtime_thread_task_t *)calloc(1, sizeof(wasmtime_thread_task_t));
  if (task == NULL) {
    wasmtime_bench_error_message(error_out, "thread: task alloc failed");
    wasmtime_module_delete(module);
    return 0;
  }
  atomic_init(&task->done, false);
  atomic_init(&task->detached, false);
  atomic_init(&task->collected, false);
  task->runtime = runtime;
  task->module = module;
  task->func_name = (char *)malloc((size_t)func_name_len);
  if (task->func_name == NULL) {
    wasmtime_bench_error_message(error_out, "thread: func name alloc failed");
    wasmtime_module_delete(module);
    free(task);
    return 0;
  }
  memcpy(task->func_name, func_name, (size_t)func_name_len);
  task->func_name_len = (size_t)func_name_len;
  task->nargs = nargs;
  task->repeat = repeat == 0 ? 1 : repeat;
  if (nargs > 0) {
    task->args = (wasmtime_val_t *)malloc(nargs * sizeof(wasmtime_val_t));
    if (task->args == NULL) {
      wasmtime_bench_error_message(error_out, "thread: args alloc failed");
      wasmtime_module_delete(module);
      free(task->func_name);
      free(task);
      return 0;
    }
    memcpy(task->args, args, nargs * sizeof(wasmtime_val_t));
  }
  if (pthread_create(&task->thread, NULL, wasmtime_thread_main, task) != 0) {
    wasmtime_bench_error_message(error_out, "thread: thread spawn failed");
    wasmtime_module_delete(module);
    if (task->args != NULL) {
      free(task->args);
    }
    free(task->func_name);
    free(task);
    return 0;
  }
  return (uint64_t)(uintptr_t)task;
}

uint64_t wasmtime_thread_runtime_spawn_wasm(
  uint64_t runtime_handle,
  const uint8_t *wasm,
  int32_t wasm_len,
  const uint8_t *func_name,
  int32_t func_name_len,
  const uint8_t *args,
  int32_t args_len,
  uint8_t *error_out
) {
  wasmtime_bench_error_clear(error_out);
#if defined(_WIN32)
  (void)runtime_handle;
  (void)wasm;
  (void)wasm_len;
  (void)func_name;
  (void)func_name_len;
  (void)args;
  (void)args_len;
  wasmtime_bench_error_message(error_out, "thread: spawn not supported on windows");
  return 0;
#else
  return wasmtime_thread_runtime_spawn_wasm_impl(
    runtime_handle,
    wasm,
    wasm_len,
    false,
    func_name,
    func_name_len,
    args,
    args_len,
    1,
    error_out
  );
#endif
}

uint64_t wasmtime_thread_runtime_spawn_wasm_repeat(
  uint64_t runtime_handle,
  const uint8_t *wasm,
  int32_t wasm_len,
  const uint8_t *func_name,
  int32_t func_name_len,
  const uint8_t *args,
  int32_t args_len,
  int32_t repeat,
  uint8_t *error_out
) {
  wasmtime_bench_error_clear(error_out);
#if defined(_WIN32)
  (void)runtime_handle;
  (void)wasm;
  (void)wasm_len;
  (void)func_name;
  (void)func_name_len;
  (void)args;
  (void)args_len;
  (void)repeat;
  wasmtime_bench_error_message(error_out, "thread: spawn not supported on windows");
  return 0;
#else
  if (repeat <= 0) {
    wasmtime_bench_error_message(error_out, "thread: repeat must be > 0");
    return 0;
  }
  return wasmtime_thread_runtime_spawn_wasm_impl(
    runtime_handle,
    wasm,
    wasm_len,
    false,
    func_name,
    func_name_len,
    args,
    args_len,
    (size_t)repeat,
    error_out
  );
#endif
}

uint64_t wasmtime_thread_runtime_spawn_cwasm(
  uint64_t runtime_handle,
  const uint8_t *cwasm,
  int32_t cwasm_len,
  const uint8_t *func_name,
  int32_t func_name_len,
  const uint8_t *args,
  int32_t args_len,
  uint8_t *error_out
) {
  wasmtime_bench_error_clear(error_out);
#if defined(_WIN32)
  (void)runtime_handle;
  (void)cwasm;
  (void)cwasm_len;
  (void)func_name;
  (void)func_name_len;
  (void)args;
  (void)args_len;
  wasmtime_bench_error_message(error_out, "thread: spawn not supported on windows");
  return 0;
#else
  return wasmtime_thread_runtime_spawn_wasm_impl(
    runtime_handle,
    cwasm,
    cwasm_len,
    true,
    func_name,
    func_name_len,
    args,
    args_len,
    1,
    error_out
  );
#endif
}

uint64_t wasmtime_thread_runtime_spawn_cwasm_repeat(
  uint64_t runtime_handle,
  const uint8_t *cwasm,
  int32_t cwasm_len,
  const uint8_t *func_name,
  int32_t func_name_len,
  const uint8_t *args,
  int32_t args_len,
  int32_t repeat,
  uint8_t *error_out
) {
  wasmtime_bench_error_clear(error_out);
#if defined(_WIN32)
  (void)runtime_handle;
  (void)cwasm;
  (void)cwasm_len;
  (void)func_name;
  (void)func_name_len;
  (void)args;
  (void)args_len;
  (void)repeat;
  wasmtime_bench_error_message(error_out, "thread: spawn not supported on windows");
  return 0;
#else
  if (repeat <= 0) {
    wasmtime_bench_error_message(error_out, "thread: repeat must be > 0");
    return 0;
  }
  return wasmtime_thread_runtime_spawn_wasm_impl(
    runtime_handle,
    cwasm,
    cwasm_len,
    true,
    func_name,
    func_name_len,
    args,
    args_len,
    (size_t)repeat,
    error_out
  );
#endif
}

bool wasmtime_thread_runtime_join(uint64_t handle, uint8_t *error_out) {
  wasmtime_bench_error_clear(error_out);
#if defined(_WIN32)
  (void)handle;
  wasmtime_bench_error_message(error_out, "thread: join not supported on windows");
  return false;
#else
  if (handle == 0) {
    wasmtime_bench_error_message(error_out, "thread: handle invalid");
    return false;
  }
  wasmtime_thread_task_t *task = (wasmtime_thread_task_t *)(uintptr_t)handle;
  if (!wasmtime_thread_task_mark_collected(task)) {
    wasmtime_bench_error_message(error_out, "thread: handle already detached");
    return false;
  }
  pthread_join(task->thread, NULL);
  bool ok = task->error == NULL;
  if (!ok) {
    wasmtime_bench_error_take(error_out, task->error);
    task->error = NULL;
  }
  wasmtime_thread_task_cleanup(task);
  return ok;
#endif
}

bool wasmtime_thread_runtime_try_join(uint64_t handle, uint8_t *error_out) {
  wasmtime_bench_error_clear(error_out);
#if defined(_WIN32)
  (void)handle;
  wasmtime_bench_error_message(error_out, "thread: try_join not supported on windows");
  return false;
#else
  if (handle == 0) {
    wasmtime_bench_error_message(error_out, "thread: handle invalid");
    return false;
  }
  wasmtime_thread_task_t *task = (wasmtime_thread_task_t *)(uintptr_t)handle;
  if (!atomic_load_explicit(&task->done, memory_order_acquire)) {
    return false;
  }
  if (!wasmtime_thread_task_mark_collected(task)) {
    wasmtime_bench_error_message(error_out, "thread: handle already detached");
    return false;
  }
  pthread_join(task->thread, NULL);
  bool ok = task->error == NULL;
  if (!ok) {
    wasmtime_bench_error_take(error_out, task->error);
    task->error = NULL;
  }
  wasmtime_thread_task_cleanup(task);
  return true;
#endif
}

bool wasmtime_thread_runtime_detach(uint64_t handle, uint8_t *error_out) {
  wasmtime_bench_error_clear(error_out);
#if defined(_WIN32)
  (void)handle;
  wasmtime_bench_error_message(error_out, "thread: detach not supported on windows");
  return false;
#else
  if (handle == 0) {
    wasmtime_bench_error_message(error_out, "thread: handle invalid");
    return false;
  }
  wasmtime_thread_task_t *task = (wasmtime_thread_task_t *)(uintptr_t)handle;
  atomic_store_explicit(&task->detached, true, memory_order_release);
  if (atomic_load_explicit(&task->done, memory_order_acquire)) {
    if (!wasmtime_thread_task_mark_collected(task)) {
      wasmtime_bench_error_message(error_out, "thread: handle already detached");
      return false;
    }
    pthread_join(task->thread, NULL);
    bool ok = task->error == NULL;
    if (!ok) {
      wasmtime_bench_error_take(error_out, task->error);
      task->error = NULL;
    }
    wasmtime_thread_task_cleanup(task);
    return ok;
  }
  if (pthread_detach(task->thread) != 0) {
    wasmtime_bench_error_message(error_out, "thread: detach failed");
    return false;
  }
  return true;
#endif
}

bool wasmtime_thread_runtime_mem_write(
  uint64_t runtime_handle,
  uint64_t offset,
  const uint8_t *src,
  int32_t len,
  uint8_t *error_out
) {
  wasmtime_bench_error_clear(error_out);
#if defined(_WIN32)
  (void)runtime_handle;
  (void)offset;
  (void)src;
  (void)len;
  wasmtime_bench_error_message(error_out, "thread: mem_write not supported on windows");
  return false;
#else
  if (runtime_handle == 0) {
    wasmtime_bench_error_message(error_out, "thread: runtime handle invalid");
    return false;
  }
  if (len < 0) {
    wasmtime_bench_error_message(error_out, "thread: mem_write length invalid");
    return false;
  }
  uint64_t length = (uint64_t)len;
  if (length > 0 && src == NULL) {
    wasmtime_bench_error_message(error_out, "thread: mem_write source missing");
    return false;
  }
  wasmtime_thread_runtime_t *runtime =
    (wasmtime_thread_runtime_t *)(uintptr_t)runtime_handle;
  if (runtime->shared == NULL) {
    wasmtime_bench_error_message(error_out, "thread: shared memory missing");
    return false;
  }
  uint8_t *data = wasmtime_sharedmemory_data(runtime->shared);
  size_t data_size = wasmtime_sharedmemory_data_size(runtime->shared);
  if (data == NULL) {
    wasmtime_bench_error_message(error_out, "thread: shared memory data unavailable");
    return false;
  }
  uint64_t size = (uint64_t)data_size;
  if (offset > size || length > size - offset) {
    wasmtime_bench_error_message(error_out, "thread: mem_write out of bounds");
    return false;
  }
  if (length > 0) {
    memcpy(data + offset, src, (size_t)length);
  }
  return true;
#endif
}

bool wasmtime_thread_runtime_mem_read(
  uint64_t runtime_handle,
  uint64_t offset,
  uint8_t *dst,
  int32_t len,
  uint8_t *error_out
) {
  wasmtime_bench_error_clear(error_out);
#if defined(_WIN32)
  (void)runtime_handle;
  (void)offset;
  (void)dst;
  (void)len;
  wasmtime_bench_error_message(error_out, "thread: mem_read not supported on windows");
  return false;
#else
  if (runtime_handle == 0) {
    wasmtime_bench_error_message(error_out, "thread: runtime handle invalid");
    return false;
  }
  if (len < 0) {
    wasmtime_bench_error_message(error_out, "thread: mem_read length invalid");
    return false;
  }
  uint64_t length = (uint64_t)len;
  if (length > 0 && dst == NULL) {
    wasmtime_bench_error_message(error_out, "thread: mem_read dest missing");
    return false;
  }
  wasmtime_thread_runtime_t *runtime =
    (wasmtime_thread_runtime_t *)(uintptr_t)runtime_handle;
  if (runtime->shared == NULL) {
    wasmtime_bench_error_message(error_out, "thread: shared memory missing");
    return false;
  }
  uint8_t *data = wasmtime_sharedmemory_data(runtime->shared);
  size_t data_size = wasmtime_sharedmemory_data_size(runtime->shared);
  if (data == NULL) {
    wasmtime_bench_error_message(error_out, "thread: shared memory data unavailable");
    return false;
  }
  uint64_t size = (uint64_t)data_size;
  if (offset > size || length > size - offset) {
    wasmtime_bench_error_message(error_out, "thread: mem_read out of bounds");
    return false;
  }
  if (length > 0) {
    memcpy(dst, data + offset, (size_t)length);
  }
  return true;
#endif
}

uint64_t wasmtime_bench_os_shared_ring(
  int32_t items,
  int32_t slots,
  uint8_t *error_out,
  uint8_t *prod_spins_out,
  uint8_t *cons_spins_out
) {
  wasmtime_bench_error_clear(error_out);
  wasmtime_bench_clear_u64(prod_spins_out);
  wasmtime_bench_clear_u64(cons_spins_out);
#if defined(_WIN32)
  (void)items;
  (void)slots;
  wasmtime_bench_error_message(error_out, "bench: os shared memory not supported on windows");
  return 0;
#else
  if (items <= 0 || slots <= 1) {
    wasmtime_bench_error_message(error_out, "bench: invalid items or slots");
    return 0;
  }
  if ((slots & (slots - 1)) != 0) {
    wasmtime_bench_error_message(error_out, "bench: slots must be power of two");
    return 0;
  }
  if ((uint64_t)items > UINT32_MAX) {
    wasmtime_bench_error_message(error_out, "bench: items exceed i32");
    return 0;
  }
  size_t header_size = sizeof(wasmtime_ring_header_t);
  if (header_size != 32) {
    wasmtime_bench_error_message(error_out, "bench: ring header size mismatch");
    return 0;
  }
  size_t size = header_size + (size_t)slots * sizeof(uint32_t);
  void *mem = mmap(
    NULL,
    size,
    PROT_READ | PROT_WRITE,
    MAP_SHARED | MAP_ANONYMOUS,
    -1,
    0
  );
  if (mem == MAP_FAILED) {
    wasmtime_bench_error_message(error_out, "bench: mmap failed");
    return 0;
  }
  wasmtime_ring_header_t *ring = (wasmtime_ring_header_t *)mem;
  uint32_t *data = (uint32_t *)((uint8_t *)mem + header_size);
  atomic_store_explicit(&ring->head, 0, memory_order_relaxed);
  atomic_store_explicit(&ring->tail, 0, memory_order_relaxed);
  ring->sum = 0;
  memset(data, 0, (size_t)slots * sizeof(uint32_t));
  pthread_t threads[2];
  wasmtime_os_ring_thread_args_t args[2];
  uint32_t mask = (uint32_t)(slots - 1);
  args[0].ring = ring;
  args[0].data = data;
  args[0].items = (uint32_t)items;
  args[0].mask = mask;
  args[0].ready_count = NULL;
  args[0].start_flag = NULL;
  args[1] = args[0];
  uint64_t start = moonbit_clock_now_ns();
  int32_t started = 0;
  if (pthread_create(&threads[started], NULL, wasmtime_os_ring_producer_main, &args[0]) == 0) {
    started++;
  }
  if (pthread_create(&threads[started], NULL, wasmtime_os_ring_consumer_main, &args[1]) == 0) {
    started++;
  }
  for (int32_t i = 0; i < started; i++) {
    pthread_join(threads[i], NULL);
  }
  uint64_t end = moonbit_clock_now_ns();
  uint32_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
  uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
  uint64_t sum = ring->sum;
  uint64_t prod_spins = ring->prod_spins;
  uint64_t cons_spins = ring->cons_spins;
  munmap(mem, size);
  if (started != 2) {
    wasmtime_bench_error_message(error_out, "bench: thread spawn failed");
    return 0;
  }
  uint64_t expected = ((uint64_t)items * (uint64_t)(items + 1)) / 2;
  if (head != (uint32_t)items || tail != (uint32_t)items) {
    wasmtime_bench_error_message(error_out, "bench: head/tail mismatch");
    return 0;
  }
  if (sum != expected) {
    wasmtime_bench_error_message(error_out, "bench: sum mismatch");
    return 0;
  }
  wasmtime_bench_write_u64(prod_spins_out, prod_spins);
  wasmtime_bench_write_u64(cons_spins_out, cons_spins);
  return end - start;
#endif
}

static uint64_t wasmtime_payload_expected_sum(uint32_t items, uint32_t payload_words) {
  uint64_t items_u64 = (uint64_t)items;
  uint64_t words_u64 = (uint64_t)payload_words;
  uint64_t base = items_u64 * (items_u64 + 1) / 2;
  uint64_t per_item = words_u64 * (words_u64 - 1) / 2;
  return words_u64 * base + items_u64 * per_item;
}

uint64_t wasmtime_bench_os_shared_payload(
  int32_t items,
  int32_t slots,
  int32_t payload_words,
  uint8_t *error_out,
  uint8_t *prod_spins_out,
  uint8_t *cons_spins_out
) {
  wasmtime_bench_error_clear(error_out);
  wasmtime_bench_clear_u64(prod_spins_out);
  wasmtime_bench_clear_u64(cons_spins_out);
#if defined(_WIN32)
  (void)items;
  (void)slots;
  (void)payload_words;
  wasmtime_bench_error_message(error_out, "bench: os shared memory not supported on windows");
  return 0;
#else
  if (items <= 0 || slots <= 1 || payload_words <= 0) {
    wasmtime_bench_error_message(error_out, "bench: invalid items, slots, or payload");
    return 0;
  }
  if ((slots & (slots - 1)) != 0) {
    wasmtime_bench_error_message(error_out, "bench: slots must be power of two");
    return 0;
  }
  if ((uint64_t)items > UINT32_MAX) {
    wasmtime_bench_error_message(error_out, "bench: items exceed i32");
    return 0;
  }
  size_t header_size = sizeof(wasmtime_ring_header_t);
  if (header_size != 32) {
    wasmtime_bench_error_message(error_out, "bench: ring header size mismatch");
    return 0;
  }
  uint64_t total_words = (uint64_t)slots * (uint64_t)payload_words;
  if (total_words == 0 || total_words > ((SIZE_MAX - header_size) / sizeof(uint32_t))) {
    wasmtime_bench_error_message(error_out, "bench: payload size too large");
    return 0;
  }
  size_t size = header_size + (size_t)total_words * sizeof(uint32_t);
  void *mem = mmap(
    NULL,
    size,
    PROT_READ | PROT_WRITE,
    MAP_SHARED | MAP_ANONYMOUS,
    -1,
    0
  );
  if (mem == MAP_FAILED) {
    wasmtime_bench_error_message(error_out, "bench: mmap failed");
    return 0;
  }
  wasmtime_ring_header_t *ring = (wasmtime_ring_header_t *)mem;
  uint32_t *data = (uint32_t *)((uint8_t *)mem + header_size);
  atomic_store_explicit(&ring->head, 0, memory_order_relaxed);
  atomic_store_explicit(&ring->tail, 0, memory_order_relaxed);
  ring->sum = 0;
  memset(data, 0, (size_t)total_words * sizeof(uint32_t));
  pthread_t threads[2];
  wasmtime_os_payload_thread_args_t args[2];
  uint32_t mask = (uint32_t)(slots - 1);
  args[0].ring = ring;
  args[0].data = data;
  args[0].items = (uint32_t)items;
  args[0].mask = mask;
  args[0].payload_words = (uint32_t)payload_words;
  args[0].ready_count = NULL;
  args[0].start_flag = NULL;
  args[1] = args[0];
  uint64_t start = moonbit_clock_now_ns();
  int32_t started = 0;
  if (pthread_create(&threads[started], NULL, wasmtime_os_payload_producer_main, &args[0]) == 0) {
    started++;
  }
  if (pthread_create(&threads[started], NULL, wasmtime_os_payload_consumer_main, &args[1]) == 0) {
    started++;
  }
  for (int32_t i = 0; i < started; i++) {
    pthread_join(threads[i], NULL);
  }
  uint64_t end = moonbit_clock_now_ns();
  uint32_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
  uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
  uint64_t sum = ring->sum;
  uint64_t prod_spins = ring->prod_spins;
  uint64_t cons_spins = ring->cons_spins;
  munmap(mem, size);
  if (started != 2) {
    wasmtime_bench_error_message(error_out, "bench: thread spawn failed");
    return 0;
  }
  uint64_t expected = wasmtime_payload_expected_sum((uint32_t)items, (uint32_t)payload_words);
  if (head != (uint32_t)items || tail != (uint32_t)items) {
    wasmtime_bench_error_message(error_out, "bench: head/tail mismatch");
    return 0;
  }
  if (sum != expected) {
    wasmtime_bench_error_message(error_out, "bench: sum mismatch");
    return 0;
  }
  wasmtime_bench_write_u64(prod_spins_out, prod_spins);
  wasmtime_bench_write_u64(cons_spins_out, cons_spins);
  return end - start;
#endif
}


uint64_t wasmtime_bench_wasm_shared_ring(
  int32_t items,
  int32_t slots,
  uint8_t *error_out,
  uint8_t *prod_spins_out,
  uint8_t *cons_spins_out
) {
  wasmtime_bench_error_clear(error_out);
  wasmtime_bench_clear_u64(prod_spins_out);
  wasmtime_bench_clear_u64(cons_spins_out);
#if defined(_WIN32)
  (void)items;
  (void)slots;
  wasmtime_bench_error_message(error_out, "bench: wasm shared memory not supported on windows");
  return 0;
#else
  if (items <= 0 || slots <= 1) {
    wasmtime_bench_error_message(error_out, "bench: invalid items or slots");
    return 0;
  }
  if ((slots & (slots - 1)) != 0) {
    wasmtime_bench_error_message(error_out, "bench: slots must be power of two");
    return 0;
  }
  if ((uint64_t)items > UINT32_MAX) {
    wasmtime_bench_error_message(error_out, "bench: items exceed i32");
    return 0;
  }
  size_t header_size = sizeof(wasmtime_ring_header_t);
  if (header_size != 32) {
    wasmtime_bench_error_message(error_out, "bench: ring header size mismatch");
    return 0;
  }
  uint64_t bytes_needed = (uint64_t)header_size + (uint64_t)slots * sizeof(uint32_t);
  uint64_t pages = (bytes_needed + 65535ULL) / 65536ULL;
  if (pages == 0) {
    pages = 1;
  }
  wasm_config_t *config = wasm_config_new();
  if (config == NULL) {
    wasmtime_bench_error_message(error_out, "bench: config_new failed");
    return 0;
  }
  wasmtime_config_wasm_threads_set(config, true);
  wasmtime_config_shared_memory_set(config, true);
  wasm_engine_t *engine = wasm_engine_new_with_config(config);
  if (engine == NULL) {
    wasm_config_delete(config);
    wasmtime_bench_error_message(error_out, "bench: engine_new_with_config failed");
    return 0;
  }
  char wat_buf[4096];
  int wat_len = snprintf(
    wat_buf,
    sizeof(wat_buf),
    "(module\n"
    "  (memory (import \"env\" \"mem\") %llu %llu shared)\n"
    "  (func (export \"produce\") (param $n i32) (param $mask i32)\n"
    "    (local $i i32) (local $head i32) (local $tail i32) (local $cap i32) (local $addr i32) (local $spins i64)\n"
    "    (local.set $i (i32.const 0))\n"
    "    (local.set $cap (i32.add (local.get $mask) (i32.const 1)))\n"
    "    (local.set $head (i32.atomic.load (i32.const 0)))\n"
    "    (local.set $spins (i64.const 0))\n"
    "    (loop $loop\n"
    "      (block $wait\n"
    "        (loop $spin\n"
    "          (local.set $tail (i32.atomic.load (i32.const 4)))\n"
    "          (br_if $wait (i32.lt_u (i32.sub (local.get $head) (local.get $tail)) (local.get $cap)))\n"
    "          (local.set $spins (i64.add (local.get $spins) (i64.const 1)))\n"
    "          (br $spin)\n"
    "        )\n"
    "      )\n"
    "      (local.set $addr\n"
    "        (i32.add\n"
    "          (i32.const 32)\n"
    "          (i32.shl (i32.and (local.get $head) (local.get $mask)) (i32.const 2))\n"
    "        )\n"
    "      )\n"
    "      (i32.store (local.get $addr) (i32.add (local.get $i) (i32.const 1)))\n"
    "      (local.set $head (i32.add (local.get $head) (i32.const 1)))\n"
    "      (i32.atomic.store (i32.const 0) (local.get $head))\n"
    "      (local.set $i (i32.add (local.get $i) (i32.const 1)))\n"
    "      (br_if $loop (i32.lt_u (local.get $i) (local.get $n)))\n"
    "    )\n"
    "    (i64.store (i32.const 16) (local.get $spins))\n"
    "  )\n"
    "  (func (export \"consume\") (param $n i32) (param $mask i32)\n"
    "    (local $i i32) (local $head i32) (local $tail i32) (local $addr i32) (local $sum i64) (local $spins i64)\n"
    "    (local.set $i (i32.const 0))\n"
    "    (local.set $tail (i32.atomic.load (i32.const 4)))\n"
    "    (local.set $sum (i64.const 0))\n"
    "    (local.set $spins (i64.const 0))\n"
    "    (loop $loop\n"
    "      (block $wait\n"
    "        (loop $spin\n"
    "          (local.set $head (i32.atomic.load (i32.const 0)))\n"
    "          (br_if $wait (i32.ne (local.get $head) (local.get $tail)))\n"
    "          (local.set $spins (i64.add (local.get $spins) (i64.const 1)))\n"
    "          (br $spin)\n"
    "        )\n"
    "      )\n"
    "      (local.set $addr\n"
    "        (i32.add\n"
    "          (i32.const 32)\n"
    "          (i32.shl (i32.and (local.get $tail) (local.get $mask)) (i32.const 2))\n"
    "        )\n"
    "      )\n"
    "      (local.set $sum\n"
    "        (i64.add (local.get $sum) (i64.extend_i32_u (i32.load (local.get $addr))))\n"
    "      )\n"
    "      (local.set $tail (i32.add (local.get $tail) (i32.const 1)))\n"
    "      (i32.atomic.store (i32.const 4) (local.get $tail))\n"
    "      (local.set $i (i32.add (local.get $i) (i32.const 1)))\n"
    "      (br_if $loop (i32.lt_u (local.get $i) (local.get $n)))\n"
    "    )\n"
    "    (i64.store (i32.const 8) (local.get $sum))\n"
    "    (i64.store (i32.const 24) (local.get $spins))\n"
    "  )\n"
    ")\n",
    (unsigned long long)pages,
    (unsigned long long)pages
  );
  if (wat_len <= 0 || (size_t)wat_len >= sizeof(wat_buf)) {
    wasm_engine_delete(engine);
    wasmtime_bench_error_message(error_out, "bench: wat buffer overflow");
    return 0;
  }
  wasm_byte_vec_t wasm = {0, NULL};
  wasmtime_error_t *err = wasmtime_wat2wasm(wat_buf, (size_t)wat_len, &wasm);
  if (err != NULL) {
    wasmtime_bench_error_take(error_out, err);
    wasm_engine_delete(engine);
    return 0;
  }
  wasmtime_module_t *module = NULL;
  err = wasmtime_module_new(engine, wasm.data, wasm.size, &module);
  wasm_byte_vec_delete(&wasm);
  if (err != NULL || module == NULL) {
    if (err != NULL) {
      wasmtime_bench_error_take(error_out, err);
    } else {
      wasmtime_bench_error_message(error_out, "bench: module_new failed");
    }
    wasm_engine_delete(engine);
    return 0;
  }
  wasm_memorytype_t *mem_ty = NULL;
  err = wasmtime_memorytype_new(pages, true, pages, false, true, 16, &mem_ty);
  if (err != NULL || mem_ty == NULL) {
    if (err != NULL) {
      wasmtime_bench_error_take(error_out, err);
    } else {
      wasmtime_bench_error_message(error_out, "bench: memorytype_new failed");
    }
    wasmtime_module_delete(module);
    wasm_engine_delete(engine);
    return 0;
  }
  wasmtime_sharedmemory_t *shared = NULL;
  err = wasmtime_sharedmemory_new(engine, mem_ty, &shared);
  wasm_memorytype_delete(mem_ty);
  if (err != NULL || shared == NULL) {
    if (err != NULL) {
      wasmtime_bench_error_take(error_out, err);
    } else {
      wasmtime_bench_error_message(error_out, "bench: sharedmemory_new failed");
    }
    wasmtime_module_delete(module);
    wasm_engine_delete(engine);
    return 0;
  }
  uint8_t *data = wasmtime_sharedmemory_data(shared);
  size_t data_size = wasmtime_sharedmemory_data_size(shared);
  if (data == NULL || data_size < (size_t)bytes_needed) {
    wasmtime_bench_error_message(error_out, "bench: shared memory data unavailable");
    wasmtime_sharedmemory_delete(shared);
    wasmtime_module_delete(module);
    wasm_engine_delete(engine);
    return 0;
  }
  memset(data, 0, (size_t)bytes_needed);
  pthread_t threads[2];
  wasmtime_wasm_ring_thread_args_t args[2];
  uint32_t mask = (uint32_t)(slots - 1);
  atomic_int error_code;
  atomic_init(&error_code, WASMTIME_BENCH_ERR_NONE);
  args[0].engine = engine;
  args[0].module = module;
  args[0].shared = shared;
  args[0].items = (uint32_t)items;
  args[0].mask = mask;
  args[0].func_name = "produce";
  args[0].func_name_len = 7;
  args[0].error_code = &error_code;
  args[0].ready_count = NULL;
  args[0].start_flag = NULL;
  args[1] = args[0];
  args[1].func_name = "consume";
  args[1].func_name_len = 7;
  uint64_t start = moonbit_clock_now_ns();
  int32_t started = 0;
  if (pthread_create(&threads[started], NULL, wasmtime_wasm_ring_thread_main, &args[0]) == 0) {
    started++;
  }
  if (pthread_create(&threads[started], NULL, wasmtime_wasm_ring_thread_main, &args[1]) == 0) {
    started++;
  }
  for (int32_t i = 0; i < started; i++) {
    pthread_join(threads[i], NULL);
  }
  uint64_t end = moonbit_clock_now_ns();
  if (started != 2) {
    wasmtime_bench_error_message(error_out, "bench: thread spawn failed");
    wasmtime_sharedmemory_delete(shared);
    wasmtime_module_delete(module);
    wasm_engine_delete(engine);
    return 0;
  }
  int code = atomic_load(&error_code);
  if (code != WASMTIME_BENCH_ERR_NONE) {
    const char *msg = "bench: wasm thread failed";
    switch (code) {
      case WASMTIME_BENCH_ERR_STORE:
        msg = "bench: store_new failed";
        break;
      case WASMTIME_BENCH_ERR_LINKER:
        msg = "bench: linker_new failed";
        break;
      case WASMTIME_BENCH_ERR_SHARED_CLONE:
        msg = "bench: sharedmemory_clone failed";
        break;
      case WASMTIME_BENCH_ERR_DEFINE:
        msg = "bench: linker_define failed";
        break;
      case WASMTIME_BENCH_ERR_INSTANTIATE:
        msg = "bench: instantiate failed";
        break;
      case WASMTIME_BENCH_ERR_EXPORT:
        msg = "bench: export_get failed";
        break;
      case WASMTIME_BENCH_ERR_EXPORT_KIND:
        msg = "bench: export kind mismatch";
        break;
      case WASMTIME_BENCH_ERR_CALL:
        msg = "bench: func_call failed";
        break;
      default:
        break;
    }
    wasmtime_bench_error_message(error_out, msg);
    wasmtime_sharedmemory_delete(shared);
    wasmtime_module_delete(module);
    wasm_engine_delete(engine);
    return 0;
  }
  uint32_t head = 0;
  uint32_t tail = 0;
  uint64_t sum = 0;
  uint64_t prod_spins = 0;
  uint64_t cons_spins = 0;
  memcpy(&head, data, sizeof(head));
  memcpy(&tail, data + 4, sizeof(tail));
  memcpy(&sum, data + 8, sizeof(sum));
  memcpy(&prod_spins, data + 16, sizeof(prod_spins));
  memcpy(&cons_spins, data + 24, sizeof(cons_spins));
  uint64_t expected = ((uint64_t)items * (uint64_t)(items + 1)) / 2;
  if (head != (uint32_t)items || tail != (uint32_t)items) {
    wasmtime_bench_error_message(error_out, "bench: head/tail mismatch");
    wasmtime_sharedmemory_delete(shared);
    wasmtime_module_delete(module);
    wasm_engine_delete(engine);
    return 0;
  }
  if (sum != expected) {
    wasmtime_bench_error_message(error_out, "bench: sum mismatch");
    wasmtime_sharedmemory_delete(shared);
    wasmtime_module_delete(module);
    wasm_engine_delete(engine);
    return 0;
  }
  wasmtime_bench_write_u64(prod_spins_out, prod_spins);
  wasmtime_bench_write_u64(cons_spins_out, cons_spins);
  wasmtime_sharedmemory_delete(shared);
  wasmtime_module_delete(module);
  wasm_engine_delete(engine);
  return end - start;
#endif
}


uint64_t wasmtime_bench_os_shared_ring_warm(
  int32_t items,
  int32_t slots,
  uint8_t *error_out,
  uint8_t *prod_spins_out,
  uint8_t *cons_spins_out
) {
  wasmtime_bench_error_clear(error_out);
  wasmtime_bench_clear_u64(prod_spins_out);
  wasmtime_bench_clear_u64(cons_spins_out);
#if defined(_WIN32)
  (void)items;
  (void)slots;
  wasmtime_bench_error_message(error_out, "bench: os shared memory not supported on windows");
  return 0;
#else
  if (items <= 0 || slots <= 1) {
    wasmtime_bench_error_message(error_out, "bench: invalid items or slots");
    return 0;
  }
  if ((slots & (slots - 1)) != 0) {
    wasmtime_bench_error_message(error_out, "bench: slots must be power of two");
    return 0;
  }
  if ((uint64_t)items > UINT32_MAX) {
    wasmtime_bench_error_message(error_out, "bench: items exceed i32");
    return 0;
  }
  size_t header_size = sizeof(wasmtime_ring_header_t);
  if (header_size != 32) {
    wasmtime_bench_error_message(error_out, "bench: ring header size mismatch");
    return 0;
  }
  size_t size = header_size + (size_t)slots * sizeof(uint32_t);
  void *mem = mmap(
    NULL,
    size,
    PROT_READ | PROT_WRITE,
    MAP_SHARED | MAP_ANONYMOUS,
    -1,
    0
  );
  if (mem == MAP_FAILED) {
    wasmtime_bench_error_message(error_out, "bench: mmap failed");
    return 0;
  }
  wasmtime_ring_header_t *ring = (wasmtime_ring_header_t *)mem;
  uint32_t *data = (uint32_t *)((uint8_t *)mem + header_size);
  atomic_store_explicit(&ring->head, 0, memory_order_relaxed);
  atomic_store_explicit(&ring->tail, 0, memory_order_relaxed);
  ring->sum = 0;
  memset(data, 0, (size_t)slots * sizeof(uint32_t));
  pthread_t threads[2];
  wasmtime_os_ring_thread_args_t args[2];
  atomic_int ready_count;
  atomic_init(&ready_count, 0);
  atomic_bool start_flag;
  atomic_init(&start_flag, false);
  uint32_t mask = (uint32_t)(slots - 1);
  args[0].ring = ring;
  args[0].data = data;
  args[0].items = (uint32_t)items;
  args[0].mask = mask;
  args[0].ready_count = &ready_count;
  args[0].start_flag = &start_flag;
  args[1] = args[0];
  int32_t started = 0;
  if (pthread_create(&threads[started], NULL, wasmtime_os_ring_producer_main, &args[0]) == 0) {
    started++;
  }
  if (pthread_create(&threads[started], NULL, wasmtime_os_ring_consumer_main, &args[1]) == 0) {
    started++;
  }
  while (atomic_load_explicit(&ready_count, memory_order_acquire) != started) {
    sched_yield();
  }
  uint64_t start = moonbit_clock_now_ns();
  atomic_store_explicit(&start_flag, true, memory_order_release);
  for (int32_t i = 0; i < started; i++) {
    pthread_join(threads[i], NULL);
  }
  uint64_t end = moonbit_clock_now_ns();
  uint32_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
  uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
  uint64_t sum = ring->sum;
  uint64_t prod_spins = ring->prod_spins;
  uint64_t cons_spins = ring->cons_spins;
  munmap(mem, size);
  if (started != 2) {
    wasmtime_bench_error_message(error_out, "bench: thread spawn failed");
    return 0;
  }
  uint64_t expected = ((uint64_t)items * (uint64_t)(items + 1)) / 2;
  if (head != (uint32_t)items || tail != (uint32_t)items) {
    wasmtime_bench_error_message(error_out, "bench: head/tail mismatch");
    return 0;
  }
  if (sum != expected) {
    wasmtime_bench_error_message(error_out, "bench: sum mismatch");
    return 0;
  }
  wasmtime_bench_write_u64(prod_spins_out, prod_spins);
  wasmtime_bench_write_u64(cons_spins_out, cons_spins);
  return end - start;
#endif
}

uint64_t wasmtime_bench_os_shared_payload_warm(
  int32_t items,
  int32_t slots,
  int32_t payload_words,
  uint8_t *error_out,
  uint8_t *prod_spins_out,
  uint8_t *cons_spins_out
) {
  wasmtime_bench_error_clear(error_out);
  wasmtime_bench_clear_u64(prod_spins_out);
  wasmtime_bench_clear_u64(cons_spins_out);
#if defined(_WIN32)
  (void)items;
  (void)slots;
  (void)payload_words;
  wasmtime_bench_error_message(error_out, "bench: os shared memory not supported on windows");
  return 0;
#else
  if (items <= 0 || slots <= 1 || payload_words <= 0) {
    wasmtime_bench_error_message(error_out, "bench: invalid items, slots, or payload");
    return 0;
  }
  if ((slots & (slots - 1)) != 0) {
    wasmtime_bench_error_message(error_out, "bench: slots must be power of two");
    return 0;
  }
  if ((uint64_t)items > UINT32_MAX) {
    wasmtime_bench_error_message(error_out, "bench: items exceed i32");
    return 0;
  }
  size_t header_size = sizeof(wasmtime_ring_header_t);
  if (header_size != 32) {
    wasmtime_bench_error_message(error_out, "bench: ring header size mismatch");
    return 0;
  }
  uint64_t total_words = (uint64_t)slots * (uint64_t)payload_words;
  if (total_words == 0 || total_words > ((SIZE_MAX - header_size) / sizeof(uint32_t))) {
    wasmtime_bench_error_message(error_out, "bench: payload size too large");
    return 0;
  }
  size_t size = header_size + (size_t)total_words * sizeof(uint32_t);
  void *mem = mmap(
    NULL,
    size,
    PROT_READ | PROT_WRITE,
    MAP_SHARED | MAP_ANONYMOUS,
    -1,
    0
  );
  if (mem == MAP_FAILED) {
    wasmtime_bench_error_message(error_out, "bench: mmap failed");
    return 0;
  }
  wasmtime_ring_header_t *ring = (wasmtime_ring_header_t *)mem;
  uint32_t *data = (uint32_t *)((uint8_t *)mem + header_size);
  atomic_store_explicit(&ring->head, 0, memory_order_relaxed);
  atomic_store_explicit(&ring->tail, 0, memory_order_relaxed);
  ring->sum = 0;
  memset(data, 0, (size_t)total_words * sizeof(uint32_t));
  pthread_t threads[2];
  wasmtime_os_payload_thread_args_t args[2];
  atomic_int ready_count;
  atomic_init(&ready_count, 0);
  atomic_bool start_flag;
  atomic_init(&start_flag, false);
  uint32_t mask = (uint32_t)(slots - 1);
  args[0].ring = ring;
  args[0].data = data;
  args[0].items = (uint32_t)items;
  args[0].mask = mask;
  args[0].payload_words = (uint32_t)payload_words;
  args[0].ready_count = &ready_count;
  args[0].start_flag = &start_flag;
  args[1] = args[0];
  int32_t started = 0;
  if (pthread_create(&threads[started], NULL, wasmtime_os_payload_producer_main, &args[0]) == 0) {
    started++;
  }
  if (pthread_create(&threads[started], NULL, wasmtime_os_payload_consumer_main, &args[1]) == 0) {
    started++;
  }
  while (atomic_load_explicit(&ready_count, memory_order_acquire) != started) {
    sched_yield();
  }
  uint64_t start = moonbit_clock_now_ns();
  atomic_store_explicit(&start_flag, true, memory_order_release);
  for (int32_t i = 0; i < started; i++) {
    pthread_join(threads[i], NULL);
  }
  uint64_t end = moonbit_clock_now_ns();
  uint32_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
  uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
  uint64_t sum = ring->sum;
  uint64_t prod_spins = ring->prod_spins;
  uint64_t cons_spins = ring->cons_spins;
  munmap(mem, size);
  if (started != 2) {
    wasmtime_bench_error_message(error_out, "bench: thread spawn failed");
    return 0;
  }
  uint64_t expected = wasmtime_payload_expected_sum((uint32_t)items, (uint32_t)payload_words);
  if (head != (uint32_t)items || tail != (uint32_t)items) {
    wasmtime_bench_error_message(error_out, "bench: head/tail mismatch");
    return 0;
  }
  if (sum != expected) {
    wasmtime_bench_error_message(error_out, "bench: sum mismatch");
    return 0;
  }
  wasmtime_bench_write_u64(prod_spins_out, prod_spins);
  wasmtime_bench_write_u64(cons_spins_out, cons_spins);
  return end - start;
#endif
}


uint64_t wasmtime_bench_wasm_shared_ring_warm(
  int32_t items,
  int32_t slots,
  uint8_t *error_out,
  uint8_t *prod_spins_out,
  uint8_t *cons_spins_out
) {
  wasmtime_bench_error_clear(error_out);
  wasmtime_bench_clear_u64(prod_spins_out);
  wasmtime_bench_clear_u64(cons_spins_out);
#if defined(_WIN32)
  (void)items;
  (void)slots;
  wasmtime_bench_error_message(error_out, "bench: wasm shared memory not supported on windows");
  return 0;
#else
  if (items <= 0 || slots <= 1) {
    wasmtime_bench_error_message(error_out, "bench: invalid items or slots");
    return 0;
  }
  if ((slots & (slots - 1)) != 0) {
    wasmtime_bench_error_message(error_out, "bench: slots must be power of two");
    return 0;
  }
  if ((uint64_t)items > UINT32_MAX) {
    wasmtime_bench_error_message(error_out, "bench: items exceed i32");
    return 0;
  }
  size_t header_size = sizeof(wasmtime_ring_header_t);
  if (header_size != 32) {
    wasmtime_bench_error_message(error_out, "bench: ring header size mismatch");
    return 0;
  }
  uint64_t bytes_needed = (uint64_t)header_size + (uint64_t)slots * sizeof(uint32_t);
  uint64_t pages = (bytes_needed + 65535ULL) / 65536ULL;
  if (pages == 0) {
    pages = 1;
  }
  wasm_config_t *config = wasm_config_new();
  if (config == NULL) {
    wasmtime_bench_error_message(error_out, "bench: config_new failed");
    return 0;
  }
  wasmtime_config_wasm_threads_set(config, true);
  wasmtime_config_shared_memory_set(config, true);
  wasm_engine_t *engine = wasm_engine_new_with_config(config);
  if (engine == NULL) {
    wasm_config_delete(config);
    wasmtime_bench_error_message(error_out, "bench: engine_new_with_config failed");
    return 0;
  }
  char wat_buf[4096];
  int wat_len = snprintf(
    wat_buf,
    sizeof(wat_buf),
    "(module\n"
    "  (memory (import \"env\" \"mem\") %llu %llu shared)\n"
    "  (func (export \"produce\") (param $n i32) (param $mask i32)\n"
    "    (local $i i32) (local $head i32) (local $tail i32) (local $cap i32) (local $addr i32) (local $spins i64)\n"
    "    (local.set $i (i32.const 0))\n"
    "    (local.set $cap (i32.add (local.get $mask) (i32.const 1)))\n"
    "    (local.set $head (i32.atomic.load (i32.const 0)))\n"
    "    (local.set $spins (i64.const 0))\n"
    "    (loop $loop\n"
    "      (block $wait\n"
    "        (loop $spin\n"
    "          (local.set $tail (i32.atomic.load (i32.const 4)))\n"
    "          (br_if $wait (i32.lt_u (i32.sub (local.get $head) (local.get $tail)) (local.get $cap)))\n"
    "          (local.set $spins (i64.add (local.get $spins) (i64.const 1)))\n"
    "          (br $spin)\n"
    "        )\n"
    "      )\n"
    "      (local.set $addr\n"
    "        (i32.add\n"
    "          (i32.const 32)\n"
    "          (i32.shl (i32.and (local.get $head) (local.get $mask)) (i32.const 2))\n"
    "        )\n"
    "      )\n"
    "      (i32.store (local.get $addr) (i32.add (local.get $i) (i32.const 1)))\n"
    "      (local.set $head (i32.add (local.get $head) (i32.const 1)))\n"
    "      (i32.atomic.store (i32.const 0) (local.get $head))\n"
    "      (local.set $i (i32.add (local.get $i) (i32.const 1)))\n"
    "      (br_if $loop (i32.lt_u (local.get $i) (local.get $n)))\n"
    "    )\n"
    "    (i64.store (i32.const 16) (local.get $spins))\n"
    "  )\n"
    "  (func (export \"consume\") (param $n i32) (param $mask i32)\n"
    "    (local $i i32) (local $head i32) (local $tail i32) (local $addr i32) (local $sum i64) (local $spins i64)\n"
    "    (local.set $i (i32.const 0))\n"
    "    (local.set $tail (i32.atomic.load (i32.const 4)))\n"
    "    (local.set $sum (i64.const 0))\n"
    "    (local.set $spins (i64.const 0))\n"
    "    (loop $loop\n"
    "      (block $wait\n"
    "        (loop $spin\n"
    "          (local.set $head (i32.atomic.load (i32.const 0)))\n"
    "          (br_if $wait (i32.ne (local.get $head) (local.get $tail)))\n"
    "          (local.set $spins (i64.add (local.get $spins) (i64.const 1)))\n"
    "          (br $spin)\n"
    "        )\n"
    "      )\n"
    "      (local.set $addr\n"
    "        (i32.add\n"
    "          (i32.const 32)\n"
    "          (i32.shl (i32.and (local.get $tail) (local.get $mask)) (i32.const 2))\n"
    "        )\n"
    "      )\n"
    "      (local.set $sum\n"
    "        (i64.add (local.get $sum) (i64.extend_i32_u (i32.load (local.get $addr))))\n"
    "      )\n"
    "      (local.set $tail (i32.add (local.get $tail) (i32.const 1)))\n"
    "      (i32.atomic.store (i32.const 4) (local.get $tail))\n"
    "      (local.set $i (i32.add (local.get $i) (i32.const 1)))\n"
    "      (br_if $loop (i32.lt_u (local.get $i) (local.get $n)))\n"
    "    )\n"
    "    (i64.store (i32.const 8) (local.get $sum))\n"
    "    (i64.store (i32.const 24) (local.get $spins))\n"
    "  )\n"
    ")\n",
    (unsigned long long)pages,
    (unsigned long long)pages
  );
  if (wat_len <= 0 || (size_t)wat_len >= sizeof(wat_buf)) {
    wasm_engine_delete(engine);
    wasmtime_bench_error_message(error_out, "bench: wat buffer overflow");
    return 0;
  }
  wasm_byte_vec_t wasm = {0, NULL};
  wasmtime_error_t *err = wasmtime_wat2wasm(wat_buf, (size_t)wat_len, &wasm);
  if (err != NULL) {
    wasmtime_bench_error_take(error_out, err);
    wasm_engine_delete(engine);
    return 0;
  }
  wasmtime_module_t *module = NULL;
  err = wasmtime_module_new(engine, wasm.data, wasm.size, &module);
  wasm_byte_vec_delete(&wasm);
  if (err != NULL || module == NULL) {
    if (err != NULL) {
      wasmtime_bench_error_take(error_out, err);
    } else {
      wasmtime_bench_error_message(error_out, "bench: module_new failed");
    }
    wasm_engine_delete(engine);
    return 0;
  }
  wasm_memorytype_t *mem_ty = NULL;
  err = wasmtime_memorytype_new(pages, true, pages, false, true, 16, &mem_ty);
  if (err != NULL || mem_ty == NULL) {
    if (err != NULL) {
      wasmtime_bench_error_take(error_out, err);
    } else {
      wasmtime_bench_error_message(error_out, "bench: memorytype_new failed");
    }
    wasmtime_module_delete(module);
    wasm_engine_delete(engine);
    return 0;
  }
  wasmtime_sharedmemory_t *shared = NULL;
  err = wasmtime_sharedmemory_new(engine, mem_ty, &shared);
  wasm_memorytype_delete(mem_ty);
  if (err != NULL || shared == NULL) {
    if (err != NULL) {
      wasmtime_bench_error_take(error_out, err);
    } else {
      wasmtime_bench_error_message(error_out, "bench: sharedmemory_new failed");
    }
    wasmtime_module_delete(module);
    wasm_engine_delete(engine);
    return 0;
  }
  uint8_t *data = wasmtime_sharedmemory_data(shared);
  size_t data_size = wasmtime_sharedmemory_data_size(shared);
  if (data == NULL || data_size < (size_t)bytes_needed) {
    wasmtime_bench_error_message(error_out, "bench: shared memory data unavailable");
    wasmtime_sharedmemory_delete(shared);
    wasmtime_module_delete(module);
    wasm_engine_delete(engine);
    return 0;
  }
  memset(data, 0, (size_t)bytes_needed);
  pthread_t threads[2];
  wasmtime_wasm_ring_thread_args_t args[2];
  uint32_t mask = (uint32_t)(slots - 1);
  atomic_int error_code;
  atomic_init(&error_code, WASMTIME_BENCH_ERR_NONE);
  atomic_int ready_count;
  atomic_init(&ready_count, 0);
  atomic_bool start_flag;
  atomic_init(&start_flag, false);
  args[0].engine = engine;
  args[0].module = module;
  args[0].shared = shared;
  args[0].items = (uint32_t)items;
  args[0].mask = mask;
  args[0].func_name = "produce";
  args[0].func_name_len = 7;
  args[0].error_code = &error_code;
  args[0].ready_count = &ready_count;
  args[0].start_flag = &start_flag;
  args[1] = args[0];
  args[1].func_name = "consume";
  args[1].func_name_len = 7;
  int32_t started = 0;
  if (pthread_create(&threads[started], NULL, wasmtime_wasm_ring_thread_main, &args[0]) == 0) {
    started++;
  }
  if (pthread_create(&threads[started], NULL, wasmtime_wasm_ring_thread_main, &args[1]) == 0) {
    started++;
  }
  while (atomic_load_explicit(&ready_count, memory_order_acquire) != started) {
    sched_yield();
  }
  uint64_t start = moonbit_clock_now_ns();
  atomic_store_explicit(&start_flag, true, memory_order_release);
  for (int32_t i = 0; i < started; i++) {
    pthread_join(threads[i], NULL);
  }
  uint64_t end = moonbit_clock_now_ns();
  if (started != 2) {
    wasmtime_bench_error_message(error_out, "bench: thread spawn failed");
    wasmtime_sharedmemory_delete(shared);
    wasmtime_module_delete(module);
    wasm_engine_delete(engine);
    return 0;
  }
  int code = atomic_load(&error_code);
  if (code != WASMTIME_BENCH_ERR_NONE) {
    const char *msg = "bench: wasm thread failed";
    switch (code) {
      case WASMTIME_BENCH_ERR_STORE:
        msg = "bench: store_new failed";
        break;
      case WASMTIME_BENCH_ERR_LINKER:
        msg = "bench: linker_new failed";
        break;
      case WASMTIME_BENCH_ERR_SHARED_CLONE:
        msg = "bench: sharedmemory_clone failed";
        break;
      case WASMTIME_BENCH_ERR_DEFINE:
        msg = "bench: linker_define failed";
        break;
      case WASMTIME_BENCH_ERR_INSTANTIATE:
        msg = "bench: instantiate failed";
        break;
      case WASMTIME_BENCH_ERR_EXPORT:
        msg = "bench: export_get failed";
        break;
      case WASMTIME_BENCH_ERR_EXPORT_KIND:
        msg = "bench: export kind mismatch";
        break;
      case WASMTIME_BENCH_ERR_CALL:
        msg = "bench: func_call failed";
        break;
      default:
        break;
    }
    wasmtime_bench_error_message(error_out, msg);
    wasmtime_sharedmemory_delete(shared);
    wasmtime_module_delete(module);
    wasm_engine_delete(engine);
    return 0;
  }
  uint32_t head = 0;
  uint32_t tail = 0;
  uint64_t sum = 0;
  uint64_t prod_spins = 0;
  uint64_t cons_spins = 0;
  memcpy(&head, data, sizeof(head));
  memcpy(&tail, data + 4, sizeof(tail));
  memcpy(&sum, data + 8, sizeof(sum));
  memcpy(&prod_spins, data + 16, sizeof(prod_spins));
  memcpy(&cons_spins, data + 24, sizeof(cons_spins));
  uint64_t expected = ((uint64_t)items * (uint64_t)(items + 1)) / 2;
  if (head != (uint32_t)items || tail != (uint32_t)items) {
    wasmtime_bench_error_message(error_out, "bench: head/tail mismatch");
    wasmtime_sharedmemory_delete(shared);
    wasmtime_module_delete(module);
    wasm_engine_delete(engine);
    return 0;
  }
  if (sum != expected) {
    wasmtime_bench_error_message(error_out, "bench: sum mismatch");
    wasmtime_sharedmemory_delete(shared);
    wasmtime_module_delete(module);
    wasm_engine_delete(engine);
    return 0;
  }
  wasmtime_bench_write_u64(prod_spins_out, prod_spins);
  wasmtime_bench_write_u64(cons_spins_out, cons_spins);
  wasmtime_sharedmemory_delete(shared);
  wasmtime_module_delete(module);
  wasm_engine_delete(engine);
  return end - start;
#endif
}
