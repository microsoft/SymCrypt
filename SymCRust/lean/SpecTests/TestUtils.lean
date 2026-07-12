import Mathlib.Data.List.Defs
import Mathlib.Data.Vector.Defs
import Aeneas
import Lean.Data.Json

/-!
# Test Infrastructure Utilities

Shared helpers for test vectors and benchmarking across all algorithm specs.
Not part of any cryptographic specification.

- **Hex conversion**: `Hex.toBytes?`, `Hex.toVector?`, `Byte.toHex`,
  `Vector.toHex` — parse and print hex strings for test vectors.
- **`Bytes n`**: alias for the Aeneas byte vector `Vector Byte n`.
- **JSON parsing**: `TestCase`, `TestGroup`, `ExpectedResults` — structures
  for deserializing NIST CAVP test vector files.
- **Test helpers**: `expect` (compare and report mismatches), `time`
  (benchmark a function with timing output).
-/

open Lean Json

-- individual test case
structure TestCase where
  tcId : Nat    -- Test case ID
  c    : String -- Ciphertext or encapsulated key (hex string)
  k    : String -- Expected key or output (hex string)
  deriving FromJson, Repr

-- collection of test cases
structure TestGroup where
  tgId  : Nat           -- Test group ID
  tests : Array TestCase
  deriving FromJson, Repr

-- top-level expectedResults JSON object.
structure ExpectedResults where
  vsId      : Nat
  algorithm : String
  mode      : String
  revision  : String
  isSample  : Bool
  testGroups : Array TestGroup
  deriving FromJson, Repr

namespace Spec.Utils

open Lean

abbrev Bytes (n : Nat) := Vector Byte n

def Byte.toHex (b : Byte) : Char :=
  if b < 10 then
    Char.ofNat ('0'.toNat + b.val)
  else
    Char.ofNat ('a'.toNat + (b.val - 10))

def Vector.toHex {n} (v : Bytes n) (trunc : Option Nat := .some 96): String :=
  Id.run do
    let mut s := ""
    for b in v do
      s := s.push (Byte.toHex (b / 16))
      s := s.push (Byte.toHex (b % 16))
    match trunc with
    | .some ℓ => s :=  (s.take (ℓ - 13)).toString ++ "..." ++ s.drop (n * 2 - 13)
    | .none => ()
    pure s

instance instToStringBytes {n} : ToString (Bytes n) where
  toString v := Vector.toHex v

def HexChar.toByte? (c : Char) : Option Byte :=
  if '0' ≤ c ∧ c ≤ '9' then some (c.toNat - '0'.toNat)
  else if 'A' ≤ c ∧ c ≤ 'F' then some (10 + (c.toNat - 'A'.toNat))
  else if 'a' ≤ c ∧ c ≤ 'f' then some (10 + (c.toNat - 'a'.toNat))
  else none

def Hex.toBytes? (s : String) : Option (Array Byte) :=
  let rec go : List Char → Array Byte → Option (Array Byte)
    | hi :: lo :: rest, acc => do
        let hi ← HexChar.toByte? hi
        let lo ← HexChar.toByte? lo
        go rest (acc.push (16 * hi + lo))
    | [], acc => some acc
    | _, _ => none
  go s.toList #[]

def Hex.toVector? (s : String) (n : Nat) : Option (Bytes n) := do
  let arr ← Hex.toBytes? s
  if h : arr.size = n then
    pure ⟨arr, h⟩
  else
    none

syntax "v!" str : term
macro_rules
  | `(v! $s:str) => do
      let hex := s.getString
      if hex.length % 2 ≠ 0 then
        Macro.throwError s!"hex!: odd number ({hex.length}) of hex characters (must be even)."
      let n := Lean.quote (hex.length / 2)
      let h := Lean.quote hex
      `(match Hex.toVector? $h $n with
        | some a => a
        | none => panic! ("hex!: invalid hex literal: " ++ $h))

def expect {n} (label : String) (expected actual : Bytes n) : IO Unit := do
  if expected ≠ actual then
    let diff := Vector.ofFn (n := n) fun i => expected[i]! - actual[i]!
    IO.println s!"✘ {label}"
    IO.println s!"  expected: {expected}"
    IO.println s!"  got:      {actual}"
    IO.println s!"  diff:     {diff}"

end Spec.Utils
