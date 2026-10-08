"""Regenerate fixtures with the pinned, unmodified upstream Python signer.

Fetch script/signer.py from UPSTREAM_COMMIT, then pass its local path. The
signer is deliberately external; normal tests are offline and need no signer.
It requires pycryptodome for keccak256.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

UPSTREAM_COMMIT = '55b2f3e25d8d7cc0df33ccdb13becca1a168b26f'
REFERENCE_SHA256 = '8792b6af94dbf2b697902bcdad8b7b35cb813e2e67c1a2abca99bf7ba9351ed7'
HERE = Path(__file__).resolve().parent


def main():
    path = Path(sys.argv[1])
    if hashlib.sha256(path.read_bytes()).hexdigest() != REFERENCE_SHA256:
        raise ValueError('signer does not match the pinned upstream revision')
    spec = importlib.util.spec_from_file_location('sphincs_minus_signer', path)
    signer = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = signer
    spec.loader.exec_module(signer)
    s = signer

    def key(label):
        # Fixed, public test seeds. pk_seed is n=16 bytes in the high half of a word.
        seed = s.keccak256(b'chialisp sphincs-minus pk_seed ' + label) & s.N_MASK
        sk_seed = s.keccak256(b'chialisp sphincs-minus sk_seed ' + label)
        return seed, sk_seed

    def public_key(seed, root):
        return s.to_b32(seed)[:16] + s.to_b32(root)[:16]

    vectors = []

    # Exactly what upstream's Foundry test testC13VerifyFFI signs with
    # `signer.py c13 0xdeadbeef...` (keys derived from the message) and checks
    # with SphincsC13Asm.verify. Signing is deterministic, so this is the same
    # (pkSeed, pkRoot, sig) the Solidity verifier accepted in upstream CI.
    ci_message = bytes.fromhex('deadbeef' * 8)
    print('Signing upstream CI message...', flush=True)
    seed, root, sig = s.sign_variant('c13', int.from_bytes(ci_message, 'big'))
    vectors.append(dict(name='upstream-ci-deadbeef', public_key=public_key(seed, root).hex(),
                        message_hash=ci_message.hex(), signature=sig.hex()))

    message = hashlib.sha256(b'Chialisp SPHINCS- interoperability test').digest()
    for label, messages in [(b'A', [message, bytes(32), bytes([255]) * 32]),
                            (b'B', [message])]:
        seed, sk_seed = key(label)
        root = None
        for msg in messages:
            print(f'Signing key={label.decode()} message={msg.hex()[:16]}...', flush=True)
            seed, root, sig = s.sign_variant('c13', int.from_bytes(msg, 'big'),
                                             seed=seed, sk_seed=sk_seed, pk_root=root)
            assert len(sig) == 3688
            assert s.verify_c_series(seed, root, int.from_bytes(msg, 'big'), sig, s.VARIANTS['c13'])
            vectors.append(dict(name=f'{label.decode()}-{msg.hex()[:8]}',
                                public_key=public_key(seed, root).hex(),
                                message_hash=msg.hex(), signature=sig.hex()))

    data = dict(upstream_commit=UPSTREAM_COMMIT, variant='c13', vectors=vectors)
    (HERE / 'vectors.json').write_text(json.dumps(data, indent=1) + '\n')
    print(f'Wrote {len(vectors)} vectors')


if __name__ == '__main__':
    main()
