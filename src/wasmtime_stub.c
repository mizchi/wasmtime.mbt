#include "wasmtime_version.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct wasm_config_t wasm_config_t;
typedef struct wasm_engine_t wasm_engine_t;
typedef struct wasm_functype_t wasm_functype_t;
typedef struct wasm_valtype_t wasm_valtype_t;
typedef struct wasm_trap_t wasm_trap_t;
typedef struct wasmtime_caller wasmtime_caller_t;
typedef struct wasmtime_context wasmtime_context_t;
typedef struct wasmtime_error wasmtime_error_t;
typedef struct wasmtime_instance_pre wasmtime_instance_pre_t;
typedef struct wasmtime_linker wasmtime_linker_t;
typedef struct wasmtime_module wasmtime_module_t;
typedef struct wasmtime_store wasmtime_store_t;
typedef struct wasmtime_call_future wasmtime_call_future_t;

typedef float float32_t;
typedef double float64_t;

typedef struct wasmtime_func {
  uint64_t store_id;
  void *__private;
} wasmtime_func_t;

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

wasmtime_error_t *wasmtime_error_new(const char *);
wasmtime_error_t *wasmtime_config_target_set(wasm_config_t *, const char *);
wasmtime_error_t *wasmtime_config_cache_config_load(wasm_config_t *, const char *);
void wasmtime_config_cranelift_flag_enable(wasm_config_t *, const char *);
void wasmtime_config_cranelift_flag_set(wasm_config_t *, const char *, const char *);
wasmtime_store_t *wasmtime_store_new(wasm_engine_t *, void *, void (*)(void *));
void wasmtime_error_delete(wasmtime_error_t *);
void wasm_trap_delete(wasm_trap_t *);
void wasmtime_val_unroot(wasmtime_val_t *);
wasm_valtype_t *wasm_valtype_new(uint8_t);
void wasm_valtype_delete(wasm_valtype_t *);
wasm_functype_t *wasm_functype_new(
  wasm_valtype_vec_t *,
  wasm_valtype_vec_t *
);
void wasm_functype_delete(wasm_functype_t *);
bool wasmtime_call_future_poll(wasmtime_call_future_t *);
void wasmtime_call_future_delete(wasmtime_call_future_t *);
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

int32_t moonbit_ptr_sizeof(void) {
  return (int32_t)sizeof(void *);
}

void moonbit_ptr_clear(uint8_t *bytes) {
  if (bytes == NULL) {
    return;
  }
  memset(bytes, 0, sizeof(void *));
}

void wasmtime_error_delete_ptr(const uint8_t *bytes) {
  wasmtime_error_t *err = (wasmtime_error_t *)moonbit_ptr_read_raw(bytes);
  if (err != NULL) {
    wasmtime_error_delete(err);
  }
}

void wasm_trap_delete_ptr(const uint8_t *bytes) {
  wasm_trap_t *trap = (wasm_trap_t *)moonbit_ptr_read_raw(bytes);
  if (trap != NULL) {
    wasm_trap_delete(trap);
  }
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
