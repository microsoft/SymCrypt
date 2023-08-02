# Upcoming breaking changes

The following breaking changes will be made in future versions of SymCrypt.

### Create and Wipe functions will be removed from module exports for asymmetric algorithms
SymCrypt was originally designed to be statically linked into Windows components. As we've expanded
to different platforms and worked to meet changing FIPS certification requirements, it has become clear
that we must produce FIPS-certifiable SymCrypt modules, rather than attempting to certify many different
modules that statically link SymCrypt. Per FIPS requirements, callers must dynamically link these
modules. Dynamic linking also ensures that, as we expose SymCrypt functions directly to external callers
(rather than through a higher-level interface such as CNG on Windows), those callers will be able
to use the latest version of SymCrypt with the latest security fixes, without having to update their
own applications.

In building our dynamically linked libraries, we've had to reevaluate some of our API surface and think
carefully about which functions and structures are exposed to callers, to limit the number of additional
breaking changes we'll have to make in the future. Specifically, we need to ensure that the sizes of
internal structures, which are subject to change, are not exposed to callers. As part of this, we will
no longer be exporting any functions which allow the caller to calculate the size of structures used
by asymmetric functions; we will also remove the functions to create these structures from existing
buffers (e.g. SymCryptRsakeyCreate).

### SYMCRYPT_CALL annotations will be added to some functions that are missing them
This is a potentially ABI-breaking change on Windows x86.

### SYMCRYPT_VERSION_API will be renamed to SYMCRYPT_VERSION_MAJOR
This is for consistency with the Semantic Versioning specification, as well as various tooling.