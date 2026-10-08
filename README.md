# SPHINCS- (C13) in Chialisp 26 — experimental

> [!CAUTION]
> **Untested, unaudited experimental code. Do not use it for anything.**
>
> This is a personal experiment, written quickly to see what a
> Chialisp port of an Ethereum post-quantum signature verifier looks like. It
> has had no cryptographic review, no independent testing and no real-world use.
> The underlying SPHINCS- scheme is itself a research prototype that its author
> marks as not for production use. Do not lock funds with it, deploy it, or
> build on it. If you want to work in this area, start from the projects linked
> below instead.

## What this is

`verify.clsp` is a Chialisp port of one Ethereum signature verifier:
`src/keccak/SPHINCs-C13Asm.sol` from [nconsigny/SPHINCS-](https://github.com/nconsigny/SPHINCS-)
at commit [`55b2f3e2`](https://github.com/nconsigny/SPHINCS-/tree/55b2f3e25d8d7cc0df33ccdb13becca1a168b26f).
SPHINCS- is a family of stateless hash-based signature variants tuned for cheap
on-chain verification; C13 is the variant upstream lists as cheapest to verify.
The repository layout copies [chialisp-shrincs](https://github.com/bramcohen/chialisp-shrincs).

### What it does

- Verifies a C13 signature over a 32-byte message: returns `()` if valid and
  raises otherwise.
- `verify_guarded.clsp` wraps the same verifier in a softfork guard so it can
  run under today's Chia consensus rules, given the exact cost (see
  [Running on Chia](#running-on-chia-keccak256-and-the-softfork-guard)).
- Uses the same key and signature format as the Ethereum verifier, so in
  principle one signature could be checked on both chains.
- Passes a small set of test vectors made with upstream's signer, including the
  exact signature upstream's CI checked with its Solidity verifier.

### What it does not do

- **No key generation or signing.** Those come from upstream's signers.
- **No wallet, puzzle or coin integration.** It is a bare verifier program, not
  a spendable puzzle, and it emits no conditions.
- **Not a drop-in for mainnet.** The bare `verify.clsp` needs hard fork 2
  (activation height not yet set). The guarded wrapper works under today's
  rules but needs the spender to compute and supply an exact cost for every
  signature. Neither has been run on any network.
- **No security guarantees.** Beyond the scheme's own unreviewed status, this
  port may have bugs of its own; a handful of vectors and bit-flip tests is not
  verification.
- **No other variants.** Only C13 with keccak256; not C7, C11, C12, the SHA-256
  or BLAKE2b twins, or SLH-DSA.
- **No state handling.** C13 is stateless but caps each key at 2^22
  signatures; nothing here tracks or enforces that.

## Where to look instead

- [bramcohen/chialisp-shrincs](https://github.com/bramcohen/chialisp-shrincs):
  Bram Cohen's Chialisp verifier for the SHRINCS BIP draft (stateful and
  stateless hash-based signatures, SHA-256 only, runs on Chia today). This
  repository copies its structure.
- [nconsigny/SPHINCS-](https://github.com/nconsigny/SPHINCS-): the upstream
  SPHINCS- verifiers (Solidity), signers (Python, Rust/WASM), Ethereum account
  integrations and security notes.
- [SPHINCS-: efficient stateless post-quantum signature verification on the EVM](https://ethresear.ch/t/sphincs-minus-efficient-stateless-post-quantum-signature-verification-on-the-evm/25165):
  the ethresear.ch write-up of the design and trade-offs.
- [FIPS 205 (SLH-DSA)](https://csrc.nist.gov/pubs/fips/205/final): the NIST
  standard SPHINCS- departs from.

## Interface

`verify.clsp` takes the environment `(PUBLIC_KEY MESSAGE_HASH SIGNATURE)`:

- `PUBLIC_KEY`: one 32-byte atom, `pk_seed[16] || pk_root[16]`. These are the
  high 16 bytes of the EVM verifier's `pkSeed` and `pkRoot` words; the EVM
  verifier rejects keys whose low 16 bytes are not zero.
- `MESSAGE_HASH`: one 32-byte atom, the `bytes32 message` that was signed.
- `SIGNATURE`: one 3,688-byte atom in the upstream C13 wire format.

Valid signatures return `()`. Invalid signatures, incorrect lengths and pair
inputs raise. The EVM verifier returns `false` for some well-formed rejections;
here every rejection raises.

## Running on Chia: keccak256 and the softfork guard

The verifier needs the CLVM `keccak256` operator, which Chia enables in two
ways:

| | Available | Program |
| --- | --- | --- |
| Inside the softfork guard, extension 1 | Now (soft fork 6, activated at height 6,800,000) | `verify_guarded.clsp` |
| Outside the guard (`ENABLE_KECCAK_OPS_OUTSIDE_GUARD`) | From hard fork 2; height still a placeholder in `chia_rs` and `chia-blockchain` | `verify.clsp` |

Under today's rules, the bare `verify.clsp` fails with `unimplemented operator`.
`verify_guarded.clsp` runs it as `(softfork COST 1 VERIFIER (list PUBLIC_KEY
MESSAGE_HASH SIGNATURE))` and takes the environment
`(COST PUBLIC_KEY MESSAGE_HASH SIGNATURE)`. An invalid signature still raises
inside the guard and fails the spend; the test suite checks both programs
against the `chia_rs` consensus runner, with and without the hard fork 2 flag.

### The exact-cost requirement

The softfork operator fails with `softfork specified cost mismatch` unless
`COST` equals the guarded program's actual cost exactly. That cost is the
verifier's own execution cost plus 140 for entering the guard. It is
deterministic for a given public key, message and signature, but it is **not
constant**: in the fixtures it ranges from 12,987,189 to 12,995,746, probably
because integer sizes in the digest arithmetic vary with the data. A fixed
upper bound does not work.

So a spender must dry-run the verifier and put the exact figure in the
solution. `guarded_cost()` in `test_sphincs_minus.py` does this with
`chia_rs`:

```python
from chia_rs import ENABLE_KECCAK_OPS_OUTSIDE_GUARD, MEMPOOL_MODE, run_chia_program

cost, _ = run_chia_program(verify_program, args(public_key, message, signature),
                           11_000_000_000, MEMPOOL_MODE | ENABLE_KECCAK_OPS_OUTSIDE_GUARD)
COST = cost + 140
```

The dry run enables keccak256 outside the guard only so the bare verifier can
run; the operator costs the same either way.

What this means in practice:

- **Not a security problem.** `COST` is not signed, but changing it only makes
  the spend fail; it cannot make an invalid signature pass.
- **Every signer or wallet needs a CLVM runner** to compute `COST`, as part of
  building the spend.
- **The cost rules can change.** Hard fork 2 brings a new cost model
  (`NEW_COST_MODEL`), so a wallet must compute `COST` under the rules in force
  when the spend is included, and spends prepared before the fork may need
  recomputing.
- **Slightly larger solutions:** `COST` adds a few bytes per spend, and the
  wrapper is 46 bytes larger than the bare verifier.

Making the verifier's cost constant would let `COST` be a fixed puzzle
constant instead. That is probably achievable by normalizing the
data-dependent integer operations, but it has not been attempted.

## Parameters

| Parameter | Value |
| --- | --- |
| Construction | WOTS+C / FORS+C (counter grinding, ePrint 2025/2203) |
| `n` | 16 bytes |
| Hypertree | `h=22`, `d=2` (two 11-level XMSS layers) |
| FORS | `k=7`, `a=19`; last index forced to zero, so 6 trees are sent |
| WOTS | `w=8`, `l=43`, digit sum must equal 208 |
| Signature budget | 2^22 signatures per key at 128-bit security (upstream analysis) |
| Hash | keccak256 over 32-byte words, output truncated to 16 bytes |
| Address | FIPS 205 §4.2 uncompressed 32-byte ADRS |

Signature layout (3,688 bytes):

| Offset | Size | Contents |
| ---: | ---: | --- |
| 0 | 16 | Randomizer `R` |
| 16 | 112 | 7 FORS secrets (the 7th is the forced-zero tree) |
| 128 | 1,824 | 6 FORS auth paths, 19 nodes each |
| 1,952 | 868 | Layer 0: 43 WOTS chains, 4-byte count, 11 auth nodes |
| 2,820 | 868 | Layer 1: same layout |

### Hashing details

The EVM code hashes 32-byte words that hold each 16-byte value in their high
half; the Chialisp code pads values with 16 zero bytes to match. Every
tweakable hash is `keccak256(pk_seed‖0^16 ‖ ADRS ‖ payload words)[0:16]`.

- `H_msg = keccak256(pk_seed‖0^16 ‖ pk_root‖0^16 ‖ R‖0^16 ‖ message ‖ 0xff^32)`,
  read as a big-endian integer `D`.
- FORS index `i` is `(D >> 19i) & (2^19-1)` for `i < 6`. Bits 114–132 must be
  zero (FORS+C), and the hypertree index is `(D >> 133) & (2^22-1)`.
- The FORS instance is keyed by the hypertree leaf: tree address is the bottom
  subtree, word1 is the bottom leaf, and word3 folds the FORS tree number into
  the node index.
- WOTS digest is `keccak256(seed ‖ ADRS ‖ node ‖ uint256(count))`, split into
  43 3-bit digits starting from the least significant bit.

## Key generation and signing

Key generation and signing run off-chain. The upstream repository has a Python
signer (`script/signer.py`, variant `c13`), a Rust/WASM signer with BIP-39
derivation (`signer-wasm`), and Ethereum account integrations. The Python
signer needs `pycryptodome` and takes about 75 seconds per signature on a
laptop, dominated by FORS tree construction and grinding.

With the pinned signer and `pycryptodome` installed, this signs a message and
prints the three atoms for `verify.clsp`:

```python
import importlib.util
import secrets
import sys

spec = importlib.util.spec_from_file_location('signer', '/tmp/sphincs_minus_signer.py')
s = importlib.util.module_from_spec(spec)
sys.modules['signer'] = s
spec.loader.exec_module(s)

seed = int.from_bytes(secrets.token_bytes(16), 'big') << 128  # pk_seed, high half
sk_seed = int.from_bytes(secrets.token_bytes(32), 'big')
message = secrets.token_bytes(32)

seed, root, sig = s.sign_variant('c13', int.from_bytes(message, 'big'),
                                 seed=seed, sk_seed=sk_seed)
public_key = s.to_b32(seed)[:16] + s.to_b32(root)[:16]
print(public_key.hex(), message.hex(), sig.hex())
```

Pass `pk_root` back in as `pk_root=` when signing further messages to skip
rebuilding the top tree. The signer is stateless; there is no counter to
manage, but the per-key budget of 2^22 signatures still applies.

## Build and test

The verifier needs a Chialisp compiler with `*standard-cl-26*`. It was built
and tested with the `chialisp` crate at revision `ee6b17b5`. Tests use
`run`, `opc` and `brun` from `PATH`, or the `CHIALISP_RUN`, `CHIALISP_OPC` and
`CHIALISP_BRUN` environment variables. The optional consensus-runner test uses
`chia_rs` (tested with 0.50.0).

```sh
python3 -m venv .venv
.venv/bin/pip install chia_rs
.venv/bin/python -m unittest -v test_sphincs_minus
```

To build the serialized programs (`-i .` lets `verify_guarded.clsp` find
`verify.clsp`):

```sh
run verify.clsp > verify.clvm
opc verify.clvm > verify.hex
run -i . verify_guarded.clsp > verify_guarded.clvm
opc verify_guarded.clvm > verify_guarded.hex
```

## Coverage

The checked-in fixtures come from the unmodified upstream Python signer, which
self-checks each signature with its own port of the EVM verifier. Upstream has
no fixed C13 known-answer file, so the fixtures are tied to the Solidity
contract this way:

- `upstream-ci-deadbeef` is what upstream's Foundry test `testC13VerifyFFI`
  signs (`signer.py c13 0xdeadbeef…`, keys derived from the message). Signing
  is deterministic, so this is the same signature `SphincsC13Asm.verify`
  accepted in upstream CI at the pinned commit
  ([solidity job](https://github.com/nconsigny/SPHINCS-/actions/runs/30584111085/job/91011303931)).
- The independent upstream Rust signer (`signer-wasm`, `signer-c13 sign`)
  produces the same public key and signature for that message, byte for byte.
- Regenerating the vectors reproduces every fixture exactly.

The other fixtures cover two more keys, three messages (including all-zero and
all-`0xff`), and reuse of a key across messages. The tests also:

- flip bits in each public-key half, the message, and every signature region
  (randomizer, FORS secrets and auth paths, WOTS chains, grinding counts,
  hypertree auth paths);
- swap signatures across keys and messages;
- reject truncation, trailing data, wrong lengths and non-atom inputs;
- run the guarded wrapper under today's consensus flags and check that only the
  exact `COST` is accepted (`COST ± 1` and a fixed guess fail) and that bad
  signatures still fail inside the guard.

Not covered: running these vectors through the Solidity contract locally
(Foundry was not available), and more than five signing samples.

## Measured cost

With chialisp `ee6b17b5` and `chia_rs` 0.50.0 (hard fork 2 flags):

| Item | Measured value |
| --- | ---: |
| Compiled verifier | 3,595 bytes |
| Compiled guarded wrapper | 3,641 bytes |
| Signature size | 3,688 bytes |
| Execution cost in fixtures | 12.99–13.00 million |
| Guarded `COST` in fixtures | 12,987,189–12,995,746 |

The verifier does a fixed amount of work apart from the WOTS chains. Because
WOTS+C fixes the digit sum, the chain work is also constant (93 steps per
layer), so the cost varies by only about 9,000 between signatures, but it does
vary (see [the exact-cost requirement](#the-exact-cost-requirement)).

Using Chia's 11,000,000,000 cost per block and 12,000 cost per byte:

| Component | Cost | Share of block |
| --- | ---: | ---: |
| Signature bytes | 44,256,000 | 0.402% |
| Verification execution | ~13,000,000 | 0.118% |
| Signature + execution | ~57,250,000 | 0.520% |
| One verifier copy | 43,140,000 | 0.392% |
| All of the above | ~100,390,000 | 0.913% |

For comparison, the SHRINCS stateless path in chialisp-shrincs measures 5,777
signature bytes, 27.5–28.4 million execution and a 4,704-byte verifier, about
1.39–1.40% of a block in total. SPHINCS- C13 is smaller and cheaper, but it
caps a key at 2^22 signatures and depends on keccak256.

These figures exclude public-key and message bytes, atom encoding, generator
overhead and other spend costs. As with SHRINCS, a generator that shares one
verifier copy across `N` spends pays the code cost about once. The new cost
model in hard fork 2 (`NEW_COST_MODEL`) may change the execution figures.

## Possible follow-ups

- **SHA-256 twin:** upstream has `c13-sha` (`src/sha/SPHINCs-C13-SHA.sol`): the
  same construction with SHA-256, the 22-byte compressed ADRS and MSB-first
  digest parsing. A Chialisp port would run on Chia today without a softfork
  guard or `COST` parameter, but would not share signatures with the keccak EVM
  verifier.
- **Constant cost:** normalize the data-dependent integer work so the guarded
  `COST` can be a fixed constant.
- **EVM cross-check:** add Foundry and verify the same vectors with
  `SPHINCs-C13Asm.sol`.

## Regenerate vectors

Normal testing does not fetch or execute upstream code. To regenerate fixtures,
fetch the pinned signer explicitly and run the generator (about 6 minutes):

```sh
curl --fail -L https://raw.githubusercontent.com/nconsigny/SPHINCS-/55b2f3e25d8d7cc0df33ccdb13becca1a168b26f/script/signer.py -o /tmp/sphincs_minus_signer.py
.venv/bin/pip install pycryptodome
.venv/bin/python generate_vectors.py /tmp/sphincs_minus_signer.py
```

The generator verifies the signer's SHA-256 before loading it, uses fixed public
test seeds, and checks every signature with the signer's own verifier.

## License

The verifier and tooling are licensed under Apache-2.0; see [LICENSE](LICENSE).
The test vectors were produced with upstream's MIT-licensed signer.
