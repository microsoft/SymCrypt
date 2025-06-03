# Allocation strategy for SymCrypt, in Rust

This note summarizes several discussions between Sam, Son and Jonathan regarding
the allocation strategy of SymCrust, a.k.a. SymCrypt written in Rust.

## General background

SymCrypt performs heap allocations via a user-defined callback, called
SymCryptCallbackAlloc, and its counterpart SymCryptCallbackFree. These act like
C's malloc and free, except that their implementation is user-defined.
For instance, in kernel mode, these functions would be implemented with the
kernel allocator. (There is no malloc/free in the kernel.)

Heap allocations occurs in one of two situations:
- long-lived objects, which are returned to the caller; for instance, one might
  allocate a key object for ML-KEM, and return the freshly-allocated object to
  the caller
- short-lived objects, which are lexically scoped, and thus *could* live on the
  stack, but in some situations, SymCrypt chooses not to do that, in order to
  avoid blowing the stack -- for instance, stack is 12k in kernel mode, which is
  really not a whole lot.

We now review our proposed strategy for these two situations.

## Long-lived objects

Any long-lived object of type `T` that gets returned to the caller becomes a
call to `Box::new` in Rust, returning a `Box<T>` that *owns* the underlying
`T`. In other words, a function like `PMLKEMKEY MlKemKeyCreate(...)` becomes `fn
MlKemKeyCreate(...) -> Box<MlKemKey>`.

Eurydice (Rust to C compiler) emits a custom macro for heap allocations, such as
those performed by `Box::new` -- we override this macro to call
`SymCryptCallbackAlloc`, and similarly for the macro that frees heap
allocations.

A complication is that SymCrypt tries hard to limit the number of calls to the
allocator; consider, for instance, MlKemKey, which in C looks roughly like this:

```c
typedef struct {
    uint32_t alg;
    ...
    MATRIX *aTranspose;
    VECTOR *t;
    VECTOR *s;
} MLKEMKEY, *PMLKEMKEY;
```

Note that the MATRIX and VECTORs are variable-length fields -- they point to a
number of elements that depends on the choice of parameter set, and therefore, we
cannot lay them out flat in the struct.

Allocating such an object is done with a single call to the allocator in
SymCrypt.

```c
PMLKEMKEY *MlKemKeyCreate(uint32_t alg) {
    char *bump_pointer = SymCryptCallbackAlloc(sizeof(MLKEMKEY) +
        size_of_matrix_for(alg) + 2*size_of_vector_for(alg));

    PMLKEMKEY key = (PMLKEMKEY) bump_pointer;
    bump_pointer += sizeof(MLKEMKEY);

    MATRIX *aTranspose = (MATRIX*) bump_pointer;
    key.aTranspose = aTranspose;
    bump_pointer += size_of_matrix_for(alg);

    VECTOR *t = (VECTOR*) bump_pointer;
    key.t = t;
    bump_pointer += size_of_vector_for(alg);

    VECTOR *s = (VECTOR*) bump_pointer;
    key.s = s;
    bump_pointer += size_of_vector_for(alg);

    return key;
}
```

The single allocation is conceptually divided in sub-parts:

```
[--- KEY ---][--- MATRIX ------][--- VECTOR ---][--- VECTOR ---]
^            ^                  ^               ^
key          aTranspose         t               s
             = key.aTranspose   = key.t         = key.s
```

To free this allocation, it suffices to call `SymCryptCallbackFree((void*)key)` since
`key` points to the beginning of the allocation.

Translating this pattern exactly as-is to Rust is hard to achieve.

## Option 1: multiple Rust heap allocations

Each one of these four objects could be allocated using its own call to
`Box::new` -- this gives rise to the following type definition.

```rust
struct MlKemKey {
    alg: u32,
    aTranspose: Box<Matrix>, // where Matrix = [ Rows ], ...
    t: Box<Vector>, // where Vector = [ PolyElement ], ...
    s: Box<Vector>
}

fn MlKemKeyCreate(u32 alg) {
    Box::new(MlKemKey {
        alg,
        aTranspose: Box::new([EMPTY_ROW; matrix_size(alg)]),
        t: Box::new([ZERO_ELEMENT; vec_size(alg)]),
        s: Box::new([ZERO_ELEMENT; vec_size(alg)]),
    })
}
```

The type definition translates naturally to C, because `Box<T>` translates to
`T*` via Eurydice, but i) we lose contiguity and ii) emit four calls to the
system allocator.

## Option 2: single allocation, using an enum (eats too much space)

```rust
enum Alg { MlKem768, MlKem1024 }

enum Fields {
    Fields768 {
        aTranspose: [u8; 768], // fictional array types
        t: [u8; 48]
    },
    Fields1024 {
        aTranspose: [u8; 1024],
        t: [u8; 64]
    }
}

struct Key1 {
    alg: Alg,
    fields: Fields
}

fn KeyCreate1(alg: Alg) -> Box<Key1> {
    match alg {
        Alg::MlKem768 => {
            let k = Key1 { alg, fields: Fields::Fields768 {
                aTranspose: [0; 768],
                t: [0; 48]
            }};
            Box::new(k)
        }
        Alg::MlKem1024 => {
            let k = Key1 { alg, fields: Fields::Fields1024 {
                aTranspose: [0; 1024],
                t: [0; 64]
            }};
            Box::new(k)
        }
    }

}
```

We use an enumeration for all three possible combinations of variable-length
fields, and store that within the key. There are multiple caveats to this
approach.

First, the structure takes up as much space as its largest element, i.e. this
succeeds:

```rust
    assert!(std::mem::size_of::<Key1>() > 1024);
```

This is because one may mutate the fields, e.g. by doing `let mut x: Key1 =
...`, so there needs to be as much space needed as to store the largest field.

Second, this only works if one can enumerate (at compile-time) all possible
combinations of lengths for those variable-length fields. This is true for
ML-KEM, but not for other algorithms, like RSA, where the key length can be
chosen at runtime.

## Option 3: two allocations, using an enum, with an indirection

```rust
struct Key2 {
    alg: Alg,
    fields: Box<Fields>
}

fn KeyCreate2(alg: Alg) -> Box<Key2> {
    match alg {
        Alg::MlKem768 => {
            let k = Key2 { alg, fields: Box::new(Fields::Fields768{
                aTranspose: [0; 768],
                t: [0; 48]
            })};
            Box::new(k)
        }
        Alg::MlKem1024 => {
            let k = Key2 { alg, fields: Box::new(Fields::Fields1024{
                aTranspose: [0; 1024],
                t: [0; 64]
            }) };
            Box::new(k)
        }
    }
}
```

This is similar in spirit to option 1. except we group variable-length field in
one enumeration.

There are two caveats to this approach:
- we still have two calls to the allocator, and 
- the same limitation applies: this only works for cases where the possible
  lengths can be enumerated at compile-time.

## Option 4: one allocation, no indirection (does not work)

We use an unsized type, a feature of Rust intended to capture header+data
allocation patterns.

```rust
struct PreKey<U: ?Sized> {
    alg: Alg,
    fields: U,
}

type Key = PreKey<Fields>;

fn KeyCreate(alg: Alg) -> Box<Key> {
    match alg {
        Alg::MlKem768 => {
            let k: Key = Key { alg, fields: Fields::Fields768{
                aTranspose: [0; 768],
                t: [0; 48]
            } };
            Box::new(k)
        }
        Alg::MlKem1024 => {
            let k: Key = Key { alg, fields: Fields::Fields1024{
                aTranspose: [0; 1024],
                t: [0; 64]
            } };
            Box::new(k)
        }
    }

}
```

We put all the variable-length allocations together at the end of the
allocation. Sadly, this does not trigger the "unsized type" pattern, and still
uses up too much space because one might do `let mut x: Key = ... in x.fields =
...` which requires reserving as much as space as the largest element of type
`Fields`.

The unsized type feature only works if there is a single variable-length field,
i.e. if `U = [T]`.

## Option 5 (good, but does not work for long-lived objects)

We use a local bump-pointer allocator that works as follows. First, we allocate
a `Box<[u8]>`. Next, we allocate objects *within* that array of bytes; the
allocator owns the underlying `[u8]`. This works.

Next, we need to return the key to the caller. This doesn't
work because the allocator is borrowed while allocations are outstanding -- we
would need to return both the allocator (ownership of the `Box<[u8]>`) and the
pointers to the various fields. The allocator is borrowed, and thus cannot be
stored in (moved into) a struct in order to be returned.

Concretely, consider:
```
struct Key<'a> {
    data: &'a[u8]
}

fn mk_key<'a>() -> Key<'a> {
    let slab = BufferAllocator::new(&mut [0; 32]);
    let x = Vec::try_with_capacity_in(8, slab).unwrap();
    Key { data: &x }
}
```

this does not type-check because:
```
error[E0515]: cannot return value referencing temporary value
xx |     let slab = BufferAllocator::new(&mut [0; 32]);
   |                                          ------- temporary value created here
xx |     let x = Vec::try_with_capacity_in(8, slab).unwrap();
xx |     Key { data: &x }
   |     ^^^^^^^^^^^^^^^^ returns a value referencing data owned by the current function
```
in other words, you can't return a key that lives in the allocator, because the allocator
is necessarily local to your function scope.

## Option 6 (speculative)

We could write a set of unsafe getters and setters that allow borrowing from the
raw chunk of bytes in order to get a "view" of the underlying fields such as
`aTranspose`, `t` and `s`, and then terminating such borrows. This would be the
more natural Rust-ish way of doing this, but:
- how to do this in a generic way, and not for every single type that uses this
  pattern in SymCrypt, remains to be determined
- we would have to figure out how to model transmutation and unsafe code in
  order to prove that our usage is correct.

This would be a worthy abstraction to verify, though, as there are typically
alignment-related subtleties that one can easily get wrong.

## Option 7 (speculative)

We could extend Aeneas to reason about the idea of an object (the allocator)
that is loaned out, and stored (in the key object) alongside fields that borrow
from that object.

This would require extending the Aeneas borrow-checker to take into account
those patterns, and extend the proof that this remains compatible with Rust's
execution model.

This is new research but could be possible with enough time.

## Option 8 (long-run)

There is a need in the Rust community for having what is described in option 7
as a built-in feature. This is known as self-referential types.

This feature of Rust is in development and would solve this, but will not
materialize (even as a prototype) for another few years.

# Short-lived allocations (temporaries)

We now look at the case of short-lived allocations which are intended to act as
a supplemental temporary storage space (also known as "scratch space").

Sam explains that we have three layers of APIs.

- outermost functionality (i.e. SymCryptRsaSignPss) actually calls
  SymCryptCallbackAlloc to get allocate a scratch space buffer (though this
  might itself be some trivial allocator defined in SymCrypt on certain firmware
  builds (environment specific callbacks))
- intermediate functionality (i.e. SymCryptRsaPssApplySignaturePadding,
  SymCryptRsaCoreDecCrt, SymCryptModExp, etc.) uses lightweight internal scratch
  allocator which has restricted call patterns (i.e. stack-like LIFO, with
  sticky errors) for ease of reasoning and correctness
- lowest level functionality (i.e. SymCryptModAdd) requires callers to provide a
  pointer to space of the correct size to avoid overheads from messing around
  with pointer arithmetic.

We rely on the linear allocator, an abstraction that allows allocating objects
of type `T` in a `Box<[u8]>`. See
https://gist.github.com/Nadrieril/d14921d5dc6c7695c0cf87a3b406f978

- outermost functionality calls `let scratch = BufferAllocator::new(...)`
- intermediate functionality is of the form `fn ModExpr<'a> (scratch: &mut
  BufferAllocator<'a>) { ... }` and calls `let mut x = Box::new_in(...,
  scratch)` to allocate in that temporary space
- innermost functionality is of the form `fn modAdd(px: &mut [u32])`, and the
  caller uses `&mut x` to go from `Box<[u32]>` to `&mut [u32]`

For verification, we would consider the allocator to be abstract, and ignore
(for the time being) allocation failures. We can prove later that we always
pre-allocate enough space.

The one (fixable) caveat with this approach is that the linear allocator in the
gist does not reclaim memory. SymCrypt follows a LIFO approach (stack-like
discipline); we would have to play tricks, e.g. keep a stack of addresses
handed out, so that calls to `free` can shrink the linear allocator
accordingly.
