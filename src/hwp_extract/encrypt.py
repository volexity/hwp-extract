# HwpExtract
# Copyright (C) 2024 Volexity, Inc.

"""The cryptographic routines required to encrypt/decrypt password protected HWP files."""

import hashlib

from Crypto.Cipher import AES


def pad(s: bytes) -> bytes:
    """Pads the given byte string to make its length a multiple of the block size (16 bytes).

    This function uses PKCS#7 padding scheme to pad the input byte string. It calculates
    the number of padding bytes needed and appends that many bytes, each with the value
    equal to the number of padding bytes.

    Args:
        s: The input byte string to be padded.

    Returns:
        The padded byte string.
    """
    block_size = 16
    size_of_last_block = len(s) % block_size
    if size_of_last_block == 0:
        return s
    padding_amount = block_size - size_of_last_block
    pad_bytes = bytes([padding_amount] * padding_amount)
    return s + pad_bytes


class AESCipher:
    """A class to perform AES encryption and decryption.

    Attributes:
        key: The encryption key used for AES encryption and decryption.
    """

    def __init__(self, key: bytes) -> None:
        """Initializes the AESCipher with the provided key."""
        self.key = key

    def encrypt(self, raw: bytes) -> bytes:
        """Encrypts the provided raw data using AES encryption.

        Args:
            raw: The raw bytes to encrypt.

        Returns:
            The encrypted bytes.
        """
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.encrypt(raw)

    def decrypt(self, enc: bytes) -> bytes:
        """Decrypts the provided raw data using AES encryption.

        Args:
            enc: The raw bytes to decrypt.

        Returns:
            The decrypted bytes.
        """
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.decrypt(enc)


def decrypt_data(key: bytes, data: bytes) -> bytearray:
    """Decrypts data from an HWP file using the given password.

    Args:
        key: The key to decrypt with.
        data: The data to decrypt.

    Returns:
        The decrypted data.
    """
    tmp_in = bytearray(16)
    final_data = bytearray()

    for kkk in range(0, len(data), 16):
        real_input = bytearray(data[kkk : kkk + 16])

        for i in range(128):
            enc_obj = AESCipher(key).encrypt(tmp_in)
            out = enc_obj[0]

            ff = i & 7

            tmp = 1
            for _ in range(3):
                v14 = tmp_in[tmp]

                tmp_in[tmp - 1] = ((2 * tmp_in[tmp - 1]) & 0xFF) | (tmp_in[tmp] >> 7)
                v15 = tmp_in[tmp + 1]
                v16 = ((2 * v14) & 0xFF) | (tmp_in[tmp + 1] >> 7)

                v17 = tmp_in[tmp + 2]
                tmp_in[tmp] = v16
                v18 = ((2 * v15) & 0xFF) | (v17 >> 7)

                v19 = tmp_in[tmp + 3]
                tmp_in[tmp + 1] = v18
                v20 = ((2 * v17) & 0xFF) | (v19 >> 7)

                v21 = ((2 * v19) & 0xFF) | (tmp_in[tmp + 4] >> 7)

                tmp_in[tmp + 2] = v20
                tmp_in[tmp + 3] = v21

                tmp += 5

            tmp_in[15] = ((2 * tmp_in[15]) & 0xFF) | (real_input[i >> 3] >> (7 - ff)) & 1

            real_input[i >> 3] ^= (out & 0x80) >> (i & 7)

        final_data.extend(real_input)

    return final_data


def genkey(pwd: bytes) -> bytes:
    """Generates a key from the given password using a custom algorithm.

    Args:
        pwd: The password to generate the key for.

    Returns:
        The key.
    """
    buf = bytearray(160)
    password = bytearray(pwd)

    for i in range(len(password)):
        v6 = password[i - 1] if i else 236

        v7 = (2 * v6 | (v6 >> 7)) & 0xFF

        buf[i * 2] = v7
        buf[i * 2 + 1] = password[i]

    sha1 = hashlib.sha1()
    sha1.update(buf[0 : len(password) * 2])
    h = sha1.digest()
    return h[0:16]
