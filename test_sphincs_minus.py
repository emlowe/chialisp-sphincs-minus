"""Compile Chialisp 26 and check upstream signatures plus hostile inputs."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

try:
    from chia_rs import ENABLE_KECCAK_OPS_OUTSIDE_GUARD, MEMPOOL_MODE, run_chia_program
    # keccak256 is only available outside the softfork guard from hard fork 2.
    HARD_FORK2_MODE = MEMPOOL_MODE | ENABLE_KECCAK_OPS_OUTSIDE_GUARD
except ImportError:
    run_chia_program = None

HERE = Path(__file__).resolve().parent
SIG_SIZE = 3688

# Signature regions: R, FORS secrets, FORS auth paths, then per hypertree layer
# WOTS chains, 4-byte grinding count and Merkle auth path.
REGIONS = {
    'randomizer': 0, 'fors_secret': 16, 'fors_last_secret': 112, 'fors_auth': 128,
    'fors_auth_last_tree': 128 + 5 * 304 + 303,
    'wots0': 1952, 'count0': 1952 + 688, 'auth0': 1952 + 692,
    'wots1': 2820, 'count1': 2820 + 688, 'auth1': 2820 + 692, 'last': SIG_SIZE - 1,
}


def atom(value):
    size = len(value)
    if size == 0:
        return b'\x80'
    if size == 1 and value[0] < 128:
        return value
    for width in range(1, 6):
        if size < 1 << (7 * width - 1):
            prefix = ((0xff << (8 - width)) & 0xff) | size >> (8 * (width - 1))
            tail = size & ((1 << (8 * (width - 1))) - 1)
            return bytes([prefix]) + tail.to_bytes(width - 1, 'big') + value
    raise ValueError('atom too large')


def args(*values):
    return b''.join(b'\xff' + atom(value) for value in values) + b'\x80'


def int_atom(value):
    return value.to_bytes((value.bit_length() + 8) // 8, 'big')


# Entering a softfork guard costs 140 on top of the guarded program's own cost.
GUARD_COST = 140


def guarded_cost(program, pk, msg, sig):
    """Exact COST for verify_guarded.clsp: a dry run of verify.clsp plus GUARD_COST.

    The dry run enables keccak256 outside the guard; the operator costs the same
    either way. Raises if the signature is invalid.
    """
    cost, _ = run_chia_program(program, args(pk, msg, sig), 11000000000,
                               MEMPOOL_MODE | ENABLE_KECCAK_OPS_OUTSIDE_GUARD)
    return cost + GUARD_COST


def tool(name):
    return os.environ.get(f'CHIALISP_{name.upper()}', name)


def failed(result):
    return result.returncode != 0 or result.stdout.startswith('FAIL')


class SphincsMinusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads((HERE / 'vectors.json').read_text())
        cls.vectors = cls.data['vectors']
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        compiled = subprocess.run([tool('run'), str(HERE / 'verify.clsp')],
                                  text=True, capture_output=True, check=True)
        assert not failed(compiled), compiled.stdout + compiled.stderr
        source = Path(cls.temp.name) / 'verify.clvm'
        source.write_text(compiled.stdout)
        assembled = subprocess.run([tool('opc'), str(source)],
                                   text=True, capture_output=True, check=True)
        cls.program = Path(cls.temp.name) / 'verify.hex'
        cls.program.write_text(assembled.stdout.strip())
        print(f'Compiled verifier: {len(bytes.fromhex(assembled.stdout.strip()))} bytes')
        cls.guarded = cls.compile('verify_guarded.clsp')
        print(f'Compiled guarded wrapper: {len(cls.guarded)} bytes')
        cls.costs = []

    @classmethod
    def compile(cls, name):
        compiled = subprocess.run([tool('run'), '-i', str(HERE), str(HERE / name)],
                                  text=True, capture_output=True, check=True, cwd=cls.temp.name)
        assert not failed(compiled), compiled.stdout + compiled.stderr
        source = Path(cls.temp.name) / f'{name}.clvm'
        source.write_text(compiled.stdout)
        assembled = subprocess.run([tool('opc'), str(source)],
                                   text=True, capture_output=True, check=True)
        return bytes.fromhex(assembled.stdout.strip())

    def execute(self, encoded):
        return subprocess.run(
            [tool('brun'), '-x', '-d', '-c', '-m', '11000000000', str(self.program), encoded.hex()],
            text=True, capture_output=True, timeout=30,
        )

    def verify(self, pk, msg, sig, valid):
        result = self.execute(args(pk, msg, sig))
        if valid:
            self.assertFalse(failed(result), result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip().splitlines()[-1], '80', result.stdout)
            self.costs.append(int(result.stdout.split('cost = ')[1].splitlines()[0]))
        else:
            self.assertTrue(failed(result), result.stdout + result.stderr)

    def inputs(self, vector):
        return [bytes.fromhex(vector[k]) for k in ('public_key', 'message_hash', 'signature')]

    def test_reference_vectors(self):
        for vector in self.vectors:
            with self.subTest(vector=vector['name']):
                self.verify(*self.inputs(vector), True)
        print('Measured CLVM cost per signature:', sorted(self.costs))

    def test_modified_inputs(self):
        for vector in self.vectors:
            pk, msg, sig = self.inputs(vector)
            cases = [(pk[:i] + bytes([pk[i] ^ 1]) + pk[i+1:], msg, sig) for i in (0, 15, 16, 31)]
            cases += [(pk, bytes([msg[0] ^ 1]) + msg[1:], sig), (pk, msg[:31] + bytes([msg[31] ^ 1]), sig)]
            cases += [(pk, msg, sig[:i] + bytes([sig[i] ^ 1]) + sig[i+1:]) for i in REGIONS.values()]
            cases += [(pk, msg, sig[:-1]), (pk, msg, sig + b'\x00')]
            for i, case in enumerate(cases):
                with self.subTest(vector=vector['name'], mutation=i):
                    self.verify(*case, False)

    def test_cross_key_and_message(self):
        a, b = self.vectors[0], self.vectors[-1]
        pk_a, msg_a, sig_a = self.inputs(a)
        pk_b, msg_b, sig_b = self.inputs(b)
        self.assertNotEqual(pk_a, pk_b)
        self.verify(pk_b, msg_a, sig_a, False)
        self.verify(pk_a, msg_a, sig_b, False)
        _, msg_other, _ = self.inputs(self.vectors[1])
        self.verify(pk_a, msg_other, sig_a, False)

    @unittest.skipUnless(run_chia_program, 'optional chia_rs consensus runner is unavailable')
    def test_consensus_runner(self):
        program = bytes.fromhex(self.program.read_text())
        for vector in self.vectors:
            with self.subTest(vector=vector['name']):
                cost, result = run_chia_program(program, args(*self.inputs(vector)),
                                                11000000000, HARD_FORK2_MODE)
                self.assertEqual(result.atom, b'')
                self.assertLess(cost, 11000000000)
        pk, msg, sig = self.inputs(self.vectors[0])
        with self.assertRaises(ValueError):
            run_chia_program(program, args(pk, msg, sig[:-1] + bytes([sig[-1] ^ 1])),
                             11000000000, HARD_FORK2_MODE)
        # Before hard fork 2 the bare keccak256 operator is rejected.
        with self.assertRaisesRegex(ValueError, 'unimplemented operator'):
            run_chia_program(program, args(pk, msg, sig), 11000000000, MEMPOOL_MODE)

    @unittest.skipUnless(run_chia_program, 'optional chia_rs consensus runner is unavailable')
    def test_softfork_guard(self):
        # Today's rules: no hard fork 2 flag; keccak256 only inside guard extension 1.
        program = bytes.fromhex(self.program.read_text())
        costs = set()
        for vector in self.vectors:
            pk, msg, sig = self.inputs(vector)
            cost = guarded_cost(program, pk, msg, sig)
            costs.add(cost)
            with self.subTest(vector=vector['name']):
                _, result = run_chia_program(self.guarded, args(int_atom(cost), pk, msg, sig),
                                             11000000000, MEMPOOL_MODE)
                self.assertEqual(result.atom, b'')
                for wrong in (cost - 1, cost + 1, 13000000):
                    with self.assertRaises(ValueError):
                        run_chia_program(self.guarded, args(int_atom(wrong), pk, msg, sig),
                                         11000000000, MEMPOOL_MODE)
                # A bad signature still fails the spend inside the guard.
                bad = sig[:-1] + bytes([sig[-1] ^ 1])
                with self.assertRaisesRegex(ValueError, 'clvm raise'):
                    run_chia_program(self.guarded, args(int_atom(cost), pk, msg, bad),
                                     11000000000, MEMPOOL_MODE)
        self.assertGreater(len(costs), 1, 'guarded cost is expected to vary by signature')
        print('Exact guarded COST values:', sorted(costs))

    def test_malformed_inputs(self):
        pk, msg, sig = self.inputs(self.vectors[0])
        for size in (0, 1, 31, 33, 48, 64):
            self.verify(bytes(size), msg, sig, False)
        for size in (0, 1, 31, 33):
            self.verify(pk, bytes(size), sig, False)
        for size in (0, 1, 16, 3687, 3688, 3689, 65536):
            self.verify(pk, msg, bytes(size), False)
        # Pairs are not binary strings; all three positions must fail.
        for position in range(3):
            values = [atom(pk), atom(msg), atom(sig)]
            values[position] = b'\xff\x01\x80'
            result = self.execute(b''.join(b'\xff' + value for value in values) + b'\x80')
            self.assertTrue(failed(result), result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
