from hwp_extract.encrypt import genkey, pad


def test_fake() -> None:
    from hwp_extract.encrypt import AESCipher

    plaintext = b"foobar"
    key = genkey(b"helloworld")
    ciphertext = AESCipher(key).encrypt(pad(plaintext))
    assert ciphertext == b"d\xc0\xf4\xd5\xaf3\x0f\x82R5 \xd4\x1d\x10\xc9n"
    plaintext = AESCipher(key).decrypt(pad(ciphertext))
    assert plaintext.strip(b"\n") == b"foobar"


def test_genkey() -> None:
    key = genkey(b"helloworld")
    assert key == b" z\xe2\xcaL\xd8\x7f\xcf\r\x01V\x9d\x8c\x14qZ"


def test_pad() -> None:
    padded = pad(b"foobar")
    assert padded == b"foobar\n\n\n\n\n\n\n\n\n\n"
