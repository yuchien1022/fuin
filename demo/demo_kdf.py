#!/usr/bin/env python3
"""Derive and display master key + subkeys for demo purposes."""
import ctypes
import ctypes.util
import sqlite3
import struct
import sys

password = sys.argv[1].encode()
db_path = sys.argv[2]

db = sqlite3.connect(db_path)
salt = db.execute("SELECT value FROM metadata WHERE key='salt'").fetchone()[0]
db.close()

context = b'FuinSeal'
try:
    import nacl.bindings as nb

    master_key = nb.crypto_pwhash_alg(
        outlen=32, passwd=password, salt=salt,
        opslimit=3, memlimit=67108864,
        alg=nb.crypto_pwhash_ALG_ARGON2ID13
    )

    def derive(mk, sid, n):
        return nb.crypto_generichash_blake2b_salt_personal(
            b'', key=mk,
            salt=struct.pack('<Q', sid) + b'\x00' * 8,
            person=context + b'\x00' * (16 - len(context)),
            digest_size=n
        )
except ModuleNotFoundError:
    sodium_path = ctypes.util.find_library('sodium')
    if sodium_path is None:
        raise SystemExit("libsodium not found; install PyNaCl or libsodium")

    sodium = ctypes.CDLL(sodium_path)
    sodium.sodium_init.restype = ctypes.c_int
    sodium.crypto_pwhash.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulonglong,
        ctypes.c_char_p,
        ctypes.c_ulonglong,
        ctypes.c_void_p,
        ctypes.c_ulonglong,
        ctypes.c_size_t,
        ctypes.c_int,
    ]
    sodium.crypto_pwhash.restype = ctypes.c_int
    sodium.crypto_generichash_blake2b_salt_personal.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_ulonglong,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    sodium.crypto_generichash_blake2b_salt_personal.restype = ctypes.c_int

    if sodium.sodium_init() < 0:
        raise SystemExit("libsodium initialization failed")

    master = ctypes.create_string_buffer(32)
    salt_buf = ctypes.create_string_buffer(salt, len(salt))
    if sodium.crypto_pwhash(
        master,
        32,
        password,
        len(password),
        salt_buf,
        3,
        67108864,
        2,
    ) != 0:
        raise SystemExit("Argon2id derivation failed")

    master_key = master.raw

    def derive(mk, sid, n):
        out = ctypes.create_string_buffer(n)
        key = ctypes.create_string_buffer(mk, len(mk))
        salt_personal = struct.pack('<Q', sid) + b'\x00' * 8
        personal = context + b'\x00' * (16 - len(context))
        salt_buf = ctypes.create_string_buffer(salt_personal, len(salt_personal))
        personal_buf = ctypes.create_string_buffer(personal, len(personal))
        if sodium.crypto_generichash_blake2b_salt_personal(
            out,
            n,
            None,
            0,
            key,
            len(mk),
            salt_buf,
            personal_buf,
        ) != 0:
            raise SystemExit("subkey derivation failed")
        return out.raw

print(salt.hex())
print(master_key.hex())
print(derive(master_key, 1, 32).hex())
print(derive(master_key, 2, 32).hex())
print(derive(master_key, 3, 32).hex())
