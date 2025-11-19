import binascii
from typing import Callable, Optional

from .._crypto import AEAD, CryptoError, HeaderProtection
from ..tls import CipherSuite, cipher_suite_hash, hkdf_expand_label, hkdf_extract
from .packet import (
    QuicProtocolVersion,
    decode_packet_number,
    is_long_header,
)

# Added imports. (KP)
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
import os
# End added imports. (KP)

#ADD IN HARDCODED RSA KEYS (KP)
PRIVATE_KEY = b"""-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAul+U+UutYJiippRWRPkdv5xzQj7uUQTNZnCrFbRAjYYxRDx3
YwIuX5NOFiGzt3wKWpjpedp+CQr3r/Ko7zrb7oCz8YdVHkHlRdxMuxlQKpXmwEWr
QyvFd3ASZmrkTN2roq3nj8wNI7Ly7SnMqQ1JJV81C6g45U2wLPgMvWn9evLfEK4Q
nA6H8eeF2Na2EsqRGImUo4hcJQx6TcgsMdCRgid0wGzmf1sVnoXF/QDuHvqymdM0
PZxFyUedhI1I+XmqjbgxBOH7KWf5XY8CXD4Zz5PClFp4nG0xvKZ4hlp/jj2+yVdm
Pb3XtVSUbMqyKMpN+ISP72LMnKgGFOS0Ki3ySwIDAQABAoIBABhIeeWdeaKbYJ3p
t+/WsYyUuuPHxU9jG8wcI/549Ow7rtGgO0H4N8iWLdduXrcqf0Lcp5cL494Twr/3
ExHQjnVd6ZQvuORvW4slsA20t6BE1cL5kN34pwrv3EXh6YsmWsWgeQpgYNnk6AgE
qTjhlUU8SXISYg9mduz1CNvpInDRWT6eX2Om4Yy9zyxaeCYGDA9DOzm6ToF83stw
Wt3cA0iaw34Ny7X7fORxOVkgTGagxyUsvOxHTLoqGW3hLCb/Bm8xSfFz0FY84AnJ
I+V+g6wRvbKRG3vkIANwUdFkJBdSMTp59URAic8KqT6OlGcophROX8t0+CPnBq/K
17qa6YkCgYEA6BcPvFZOMK8raWMPznZedssJxDv9JK24CR9ce16UXvZXTNcBMopT
FXOLbbDL2tjZ2kF4oliCFG5XkR+HifUwZkrOSAMEnAhn3sE1jaJtifqIq2yLEVIT
AekE5B4XErD1oCVKxdd7PPOgOA4Jvg356+svrqPnBo5hIcMWbIKcLPUCgYEAzZLU
Bfa3OIrbLFCNavgQx+h81Ne+S7V3oVmeE/4rlY1H3Q6WXyZut1kselg1v8BpZ1oB
lggcxVpfjnqXDwdPEeNnyuKSozZPVUMQOWBP0oU5U6VnEjypwcC71acSqcUjpb20
6ZrC24a4ODzSUC5zDEAar4hwqcInCQz0o4e2Gj8CgYBL+CCCeY2mifAf0vk9j6lk
IRnVTf2Sn/p5ofZXu6G9Y803rbkKnhSMFQIyqYhQ3mKQ+pVOLsKFhYjMTBHFqqhp
E1tqXvKHUIkPdRbegahxXbyWwDTVOpRWL7wWH3NV/u6nuQ08rUf9r5FmR9IQj+qa
uqUk+SmKD9jjgEQ6yJXucQKBgBDHTCDUey3VP4BFbtVtO8llM1MX7MM3I3V64AkX
tKz3JAdp2mIXu++hCp1Nt81XwgKaeQiqztZYwvXZEZ07Znu6SM1pYriJhT4bRCa6
sqknEH/AP0JgyyYyOeJ9SWur2HX9ntd2NzM9sql8ZVoAAInebY8oHrHsU81MTmdO
e1F3AoGAaj+ZSWqPz1HhYIeOwhVJIE/RvQa6pf8sGkUtZB+GDqoVaDT7UQuXkw3e
wsKn/CFHXqpJC31uVF9BhkMS7uRz/8kj+0zoNdwbDRCF5+q1IBjhYTRwbd07e8lq
jdGnTjYGomAnaZq9044Z1AHeqjCFvbRIMIbBsYRdXPXsyiplTUY=
-----END RSA PRIVATE KEY-----"""

PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAul+U+UutYJiippRWRPkd
v5xzQj7uUQTNZnCrFbRAjYYxRDx3YwIuX5NOFiGzt3wKWpjpedp+CQr3r/Ko7zrb
7oCz8YdVHkHlRdxMuxlQKpXmwEWrQyvFd3ASZmrkTN2roq3nj8wNI7Ly7SnMqQ1J
JV81C6g45U2wLPgMvWn9evLfEK4QnA6H8eeF2Na2EsqRGImUo4hcJQx6TcgsMdCR
gid0wGzmf1sVnoXF/QDuHvqymdM0PZxFyUedhI1I+XmqjbgxBOH7KWf5XY8CXD4Z
z5PClFp4nG0xvKZ4hlp/jj2+yVdmPb3XtVSUbMqyKMpN+ISP72LMnKgGFOS0Ki3y
SwIDAQAB
-----END PUBLIC KEY-----"""
#END HARD CODED RSA KEYS (KP)


CIPHER_SUITES = {
    CipherSuite.AES_128_GCM_SHA256: (b"aes-128-ecb", b"aes-128-gcm"),
    CipherSuite.AES_256_GCM_SHA384: (b"aes-256-ecb", b"aes-256-gcm"),
    CipherSuite.CHACHA20_POLY1305_SHA256: (b"chacha20", b"chacha20-poly1305"),
}
INITIAL_CIPHER_SUITE = CipherSuite.AES_128_GCM_SHA256
INITIAL_SALT_VERSION_1 = binascii.unhexlify("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
INITIAL_SALT_VERSION_2 = binascii.unhexlify("0dede3def700a6db819381be6e269dcbf9bd2ed9")
SAMPLE_SIZE = 16


Callback = Callable[[str], None]



def NoCallback(trigger: str) -> None:
    pass


class KeyUnavailableError(CryptoError):
    pass


def derive_key_iv_hp(
    *, cipher_suite: CipherSuite, secret: bytes, version: int
) -> tuple[bytes, bytes, bytes]:
    algorithm = cipher_suite_hash(cipher_suite)
    if cipher_suite in [
        CipherSuite.AES_256_GCM_SHA384,
        CipherSuite.CHACHA20_POLY1305_SHA256,
    ]:
        key_size = 32
    else:
        key_size = 16
    if version == QuicProtocolVersion.VERSION_2:
        return (
            hkdf_expand_label(algorithm, secret, b"quicv2 key", b"", key_size),
            hkdf_expand_label(algorithm, secret, b"quicv2 iv", b"", 12),
            hkdf_expand_label(algorithm, secret, b"quicv2 hp", b"", key_size),
        )
    else:
        return (
            hkdf_expand_label(algorithm, secret, b"quic key", b"", key_size),
            hkdf_expand_label(algorithm, secret, b"quic iv", b"", 12),
            hkdf_expand_label(algorithm, secret, b"quic hp", b"", key_size),
        )


class CryptoContext:
    def __init__(
        self,
        key_phase: int = 0,
        setup_cb: Callback = NoCallback,
        teardown_cb: Callback = NoCallback,
    ) -> None:
        self.aead: Optional[AEAD] = None
        self.cipher_suite: Optional[CipherSuite] = None
        self.hp: Optional[HeaderProtection] = None
        self.key_phase = key_phase
        self.secret: Optional[bytes] = None
        self.version: Optional[int] = None
        self._setup_cb = setup_cb
        self._teardown_cb = teardown_cb


    ### New functions begin
    def protected_initial_encrypter(self, payload: bytes) -> bytes:
        symmetric_key = os.urandom(32)
        iv = os.urandom(16)

        print(f"DEBUG: Symmetric key (hex): {symmetric_key.hex()}")
        print(f"DEBUG: IV (hex): {iv.hex()}")
        cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(payload) + encryptor.finalize()
        tag = encryptor.tag
        print(f"DEBUG: Ciphertext (hex): {ciphertext.hex()}")
        print(f"DEBUG: Tag (hex): {tag.hex()}")

        # Do the sandwiched encryption with the pubkey and sym key
        pub_key = load_pem_public_key(PUBLIC_KEY)
        encrypted_symmetric_key = pub_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_symmetric_key + iv + tag + ciphertext

    def protected_initial_decrypter(self, encrypted_payload: bytes) -> bytes:

        RSA_KEY_SIZE = 256
        IV_SIZE = 16
        TAG_SIZE = 16

        print(f"DEBUG: Encrypted payload length: {len(encrypted_payload)}")
        print(f"DEBUG: First 10 bytes (hex): {encrypted_payload[:10].hex()}")

        if len(encrypted_payload) < 2:
            raise ValueError(f"Encrypted payload is too short to contain symmetric key length. is {len(encrypted_payload)} bytes.")

        # Extract all the stuff from the encrypted bytes:

        encrypted_sym_key = encrypted_payload[:RSA_KEY_SIZE]
        iv = encrypted_payload[RSA_KEY_SIZE: RSA_KEY_SIZE + IV_SIZE]
        tag = encrypted_payload[RSA_KEY_SIZE + IV_SIZE:RSA_KEY_SIZE + IV_SIZE + TAG_SIZE]
        ciphertext = encrypted_payload[RSA_KEY_SIZE + IV_SIZE + TAG_SIZE:]
        print(f"DEBUG: Encrypted symmetric key (hex): {encrypted_sym_key.hex()}")
        print(f"DEBUG: Encrypted symmetric key length: {len(encrypted_sym_key)}")
        print(f"DEBUG: IV length: {len(iv)}")
        print(f"DEBUG: Tag length: {len(tag)}")
        print(f"DEBUG: Ciphertext length: {len(ciphertext)}")

        # Now decrypt our symmetric key
        private_key = load_pem_private_key(PRIVATE_KEY, password=None)
        try: 
            symmetric_key = private_key.decrypt(
                encrypted_sym_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            print(f"DEBUG: Failed to decrypt symmetric key: {e}")
            raise

        print("Encrypted symmetric key length:", len(symmetric_key))
        print("Encrypted symmetric key (first 32 bytes):", symmetric_key[:32].hex())
        # Now decrypt the payload
        cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        print(f"DEBUG: Decrypted plaintext length: {len(plaintext)}")
        print(f"DEBUG: Decrypted plaintext (hex): {plaintext.hex()}")
        return plaintext


    def encrypt_initial_packet(self, plain_header: bytes, plain_payload: bytes, packet_number: int) -> bytes:
        # payload protection
        protected_payload = self.protected_initial_encrypter(plain_payload)
        # header protection
        return self.hp.apply(plain_header, protected_payload)

    def decrypt_initial_packet(self, encrypted_packet: bytes, encrypted_offset: int, expected_packet_number: int) -> tuple[bytes, bytes, int]:
        # header protection
        plain_header, packet_number = self.hp.remove(encrypted_packet, encrypted_offset)
        first_byte = plain_header[0]
        # packet number
        pn_length = (first_byte & 0x03) + 1
        packet_number = decode_packet_number(
            packet_number, pn_length * 8, expected_packet_number
        )
        payload_start = encrypted_offset + len(plain_header)
        encrypted_payload = encrypted_packet[payload_start:]

        # payload protection
        plain_payload = self.protected_initial_decrypter(encrypted_payload)

        return plain_header, plain_payload, packet_number

    ### New functions end.
    def decrypt_packet(
        self, packet: bytes, encrypted_offset: int, expected_packet_number: int
    ) -> tuple[bytes, bytes, int, bool]:
        if self.aead is None:
            raise KeyUnavailableError("Decryption key is not available")

        # header protection
        plain_header, packet_number = self.hp.remove(packet, encrypted_offset)
        first_byte = plain_header[0]

        # packet number
        pn_length = (first_byte & 0x03) + 1
        packet_number = decode_packet_number(
            packet_number, pn_length * 8, expected_packet_number
        )

        # detect key phase change
        crypto = self
        if not is_long_header(first_byte):
            key_phase = (first_byte & 4) >> 2
            if key_phase != self.key_phase:
                crypto = next_key_phase(self)

        # payload protection
        payload = crypto.aead.decrypt(
            packet[len(plain_header) :], plain_header, packet_number
        )

        return plain_header, payload, packet_number, crypto != self

    def encrypt_packet(
        self, plain_header: bytes, plain_payload: bytes, packet_number: int
    ) -> bytes:
        assert self.is_valid(), "Encryption key is not available"

        # payload protection
        protected_payload = self.aead.encrypt(
            plain_payload, plain_header, packet_number
        )

        # header protection
        return self.hp.apply(plain_header, protected_payload)

    def is_valid(self) -> bool:
        return self.aead is not None

    def setup(self, *, cipher_suite: CipherSuite, secret: bytes, version: int) -> None:
        hp_cipher_name, aead_cipher_name = CIPHER_SUITES[cipher_suite]

        key, iv, hp = derive_key_iv_hp(
            cipher_suite=cipher_suite,
            secret=secret,
            version=version,
        )
        self.aead = AEAD(aead_cipher_name, key, iv)
        self.cipher_suite = cipher_suite
        self.hp = HeaderProtection(hp_cipher_name, hp)
        self.secret = secret
        self.version = version

        # trigger callback
        self._setup_cb("tls")

    def teardown(self) -> None:
        self.aead = None
        self.cipher_suite = None
        self.hp = None
        self.secret = None

        # trigger callback
        self._teardown_cb("tls")


def apply_key_phase(self: CryptoContext, crypto: CryptoContext, trigger: str) -> None:
    self.aead = crypto.aead
    self.key_phase = crypto.key_phase
    self.secret = crypto.secret

    # trigger callback
    self._setup_cb(trigger)


def next_key_phase(self: CryptoContext) -> CryptoContext:
    algorithm = cipher_suite_hash(self.cipher_suite)

    crypto = CryptoContext(key_phase=int(not self.key_phase))
    crypto.setup(
        cipher_suite=self.cipher_suite,
        secret=hkdf_expand_label(
            algorithm, self.secret, b"quic ku", b"", algorithm.digest_size
        ),
        version=self.version,
    )
    return crypto


class CryptoPair:
    def __init__(
        self,
        recv_setup_cb: Callback = NoCallback,
        recv_teardown_cb: Callback = NoCallback,
        send_setup_cb: Callback = NoCallback,
        send_teardown_cb: Callback = NoCallback,
    ) -> None:
        self.aead_tag_size = 16
        self.recv = CryptoContext(setup_cb=recv_setup_cb, teardown_cb=recv_teardown_cb)
        self.send = CryptoContext(setup_cb=send_setup_cb, teardown_cb=send_teardown_cb)
        self._update_key_requested = False

    # NEW
    def encrypt_initial_packet(
        self, plain_header: bytes, plain_payload: bytes, packet_number: int
    ) -> bytes:
        # forward to the send context like other encrypt
        return self.send.encrypt_initial_packet(plain_header, plain_payload, packet_number)

    def decrypt_initial_packet(
        self, encrypted_packet: bytes, encrypted_offset: int, expected_packet_number: int
    ) -> tuple[bytes, bytes, int]:
        # forward to the recv context like other decrypt
        return self.recv.decrypt_initial_packet(
            encrypted_packet, encrypted_offset, expected_packet_number
        )
    # END NEW

    def decrypt_packet(
        self, packet: bytes, encrypted_offset: int, expected_packet_number: int
    ) -> tuple[bytes, bytes, int]:
        plain_header, payload, packet_number, update_key = self.recv.decrypt_packet(
            packet, encrypted_offset, expected_packet_number
        )
        if update_key:
            self._update_key("remote_update")
        return plain_header, payload, packet_number

    def encrypt_packet(
        self, plain_header: bytes, plain_payload: bytes, packet_number: int
    ) -> bytes:
        if self._update_key_requested:
            self._update_key("local_update")
        return self.send.encrypt_packet(plain_header, plain_payload, packet_number)

    def setup_initial(self, cid: bytes, is_client: bool, version: int) -> None:
        if is_client:
            recv_label, send_label = b"server in", b"client in"
        else:
            recv_label, send_label = b"client in", b"server in"

        if version == QuicProtocolVersion.VERSION_2:
            initial_salt = INITIAL_SALT_VERSION_2
        else:
            initial_salt = INITIAL_SALT_VERSION_1

        algorithm = cipher_suite_hash(INITIAL_CIPHER_SUITE)
        initial_secret = hkdf_extract(algorithm, initial_salt, cid)
        self.recv.setup(
            cipher_suite=INITIAL_CIPHER_SUITE,
            secret=hkdf_expand_label(
                algorithm, initial_secret, recv_label, b"", algorithm.digest_size
            ),
            version=version,
        )
        self.send.setup(
            cipher_suite=INITIAL_CIPHER_SUITE,
            secret=hkdf_expand_label(
                algorithm, initial_secret, send_label, b"", algorithm.digest_size
            ),
            version=version,
        )

    def teardown(self) -> None:
        self.recv.teardown()
        self.send.teardown()

    def update_key(self) -> None:
        self._update_key_requested = True

    @property
    def key_phase(self) -> int:
        if self._update_key_requested:
            return int(not self.recv.key_phase)
        else:
            return self.recv.key_phase

    def _update_key(self, trigger: str) -> None:
        apply_key_phase(self.recv, next_key_phase(self.recv), trigger=trigger)
        apply_key_phase(self.send, next_key_phase(self.send), trigger=trigger)
        self._update_key_requested = False
