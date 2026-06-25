# symcrypt_plus_testmodule

A test-only shared library (`.dll` on Windows, `.so`/`.dylib` on POSIX) that
models the production scenario where an application:

1. **Dynamically** links the production SymCrypt module (`symcrypt.dll` on
   Windows, `libsymcrypt.so` on POSIX). For tests, the Windows DLL is
   substituted with the test-mode `symcrypttestmodule.dll`; POSIX uses the
   real production `libsymcrypt.so` built under `modules/posix/...`.
2. **Statically** links `symcrypt_plus.lib` / `libsymcrypt_plus.a` (which
   today contains the HPKE implementation).

The same `symcryptunittest` exe can then exercise HPKE against this module:

```
# Windows:
.\bin_plus_module\exe\symcryptunittest.exe +Hpke noperftests \
    "dynamic:symcrypt_plus_testmodule.dll"

# POSIX:
./exe/symcryptunittest +Hpke noperftests \
    "dynamic:./lib/generic/libsymcrypt_plus_testmodule.so"
```

## What this module exports

- **Forwarders to `symcrypttestmodule.dll`** for every base SymCrypt symbol
  (Windows only, ~840 entries). Emitted at build time by
  [`gen_combined_def.py`](gen_combined_def.py) from
  [`../module_windows/exports.def`](../module_windows/exports.def). The POSIX
  build does **not** re-export base SymCrypt symbols; references from this
  `.so` resolve to `libsymcrypt.so` via the `DT_NEEDED` dependency without
  going through this `.so`'s symbol table.
- **`SymCryptHpke*`** functions, statically linked from `symcrypt_plus`.
  [`exports_plus_local.def`](exports_plus_local.def) is the single
  hand-maintained source of truth for these local exports; build-time
  generation emits the Windows DEF, ELF version script, and Darwin
  exported-symbols list from it.
- **`SymCryptModuleInit`**, also listed locally. This module provides its own
  implementation (in [`module_plus.cpp`](module_plus.cpp)) that initialises
  both the base module and the local `symcrypt_plus`-side state.

## Why local environment callbacks

[`module_plus.cpp`](module_plus.cpp) provides its own
`SymCryptCallbackAlloc` / `SymCryptCallbackFree` (and the mutex / random
callbacks). This keeps allocations made by `symcrypt_plus` code (which is
linked statically into this module) inside this module's heap, separately
from allocations made by base SymCrypt primitives which live in the base
module's heap. Both halves use their own copy of the allocation-with-guards
infrastructure to keep that boundary honest.

## Runtime layout

### Windows
`symcrypt_plus_testmodule.dll` and `symcrypttestmodule.dll` must be
co-located at runtime so the loader can resolve the forwarders. CMake and
MSBuild outputs both already place them in the same directory.

### POSIX
`libsymcrypt_plus_testmodule.so` and `libsymcrypt.so.<API>` must be locatable
at runtime through the dynamic loader's normal rules (`DT_RUNPATH` /
`LD_LIBRARY_PATH`). CMake puts this `.so` under
`<build>/lib/generic/` alongside `libsymcrypt.so.<API>` and sets
`BUILD_RPATH=$ORIGIN`, so the layout works out of the box for local
development without any environment-variable plumbing.

## `SymCryptModuleInit` recursion: why dlopen/GetProcAddress

This module re-exports `SymCryptModuleInit`, shadowing the base module's
symbol of the same name. A naïve call to `SymCryptModuleInit(api, minor)`
from inside our own `SymCryptModuleInit` would therefore recurse infinitely.
To delegate to the base module's init, we explicitly look up its address:

- **Windows**: `GetModuleHandleA("symcrypttestmodule")` +
  `GetProcAddress(..., "SymCryptModuleInit")`. The base DLL is already loaded
  as an import dependency, so `GetModuleHandle` returns its already-loaded
  HMODULE.
- **POSIX**: `dlopen("libsymcrypt.so.<API>", RTLD_NOW | RTLD_NOLOAD)` +
  `dlsym(..., "SymCryptModuleInit")`. The base `.so` is already loaded as our
  `DT_NEEDED` dependency, so `RTLD_NOLOAD` returns a handle without
  re-loading; the matching `dlclose` keeps the refcount balanced.
