"""This module implements the communication of HAP.

The HAPServer is the point of contact to and from the world.
The HAPServerHandler manages the state of the connection and handles incoming requests.
The HAPSocket is a socket implementation that manages the "TLS" of the connection.
"""
import asyncio
import json
import logging
import struct
import uuid
from http import HTTPStatus
from urllib.parse import parse_qs, urlparse

import curve25519
import ed25519
import h11
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import pyhap.tlv as tlv
from pyhap.const import __version__
from pyhap.util import long_to_bytes

SNAPSHOT_TIMEOUT = 10

logger = logging.getLogger(__name__)

backend = default_backend()


class HAPResponse:
    def __init__(self):
        self.status_code: int = 500
        self.reason: str = "Internal Server Error"
        self.headers = []
        self.body = []
        self.shared_key = None
        self.task = None


# Various "tag" constants for HAP's TLV encoding.
class HAP_TLV_TAGS:
    REQUEST_TYPE = b"\x00"
    USERNAME = b"\x01"
    SALT = b"\x02"
    PUBLIC_KEY = b"\x03"
    PASSWORD_PROOF = b"\x04"
    ENCRYPTED_DATA = b"\x05"
    SEQUENCE_NUM = b"\x06"
    ERROR_CODE = b"\x07"
    PROOF = b"\x0A"


# Status codes for underlying HAP calls
class HAP_SERVER_STATUS:
    SUCCESS = 0
    INSUFFICIENT_PRIVILEGES = -70401
    SERVICE_COMMUNICATION_FAILURE = -70402
    RESOURCE_BUSY = -70403
    READ_ONLY_CHARACTERISTIC = -70404
    WRITE_ONLY_CHARACTERISTIC = -70405
    NOTIFICATION_NOT_SUPPORTED = -70406
    OUT_OF_RESOURCE = -70407
    OPERATION_TIMED_OUT = -70408
    RESOURCE_DOES_NOT_EXIST = -70409
    INVALID_VALUE_IN_REQUEST = -70410
    INSUFFICIENT_AUTHORIZATION = -70411


# Error codes and the like, guessed by packet inspection
class HAP_OPERATION_CODE:
    INVALID_REQUEST = b"\x02"
    INVALID_SIGNATURE = b"\x04"


class HAP_CRYPTO:
    HKDF_KEYLEN = 32  # bytes, length of expanded HKDF keys
    HKDF_HASH = hashes.SHA512()  # Hash function to use in key expansion
    TAG_LENGTH = 16  # ChaCha20Poly1305 tag length
    TLS_NONCE_LEN = 12  # bytes, length of TLS encryption nonce


def _pad_tls_nonce(nonce, total_len=HAP_CRYPTO.TLS_NONCE_LEN):
    """Pads a nonce with zeroes so that total_len is reached."""
    return nonce.rjust(total_len, b"\x00")


def hap_hkdf(key, salt, info):
    """Just a shorthand."""
    hkdf = HKDF(
        algorithm=HAP_CRYPTO.HKDF_HASH,
        length=HAP_CRYPTO.HKDF_KEYLEN,
        salt=salt,
        info=info,
        backend=backend,
    )
    return hkdf.derive(key)


class TimeoutException(Exception):
    pass


class UnprivilegedRequestException(Exception):
    pass


class NotAllowedInStateException(Exception):
    pass


class HAPServerHandler:
    """Manages HAP connection state and handles incoming HTTP requests."""

    # Mapping from paths to methods that handle them.
    HANDLERS = {
        "POST": {
            "/pair-setup": "handle_pairing",
            "/pair-verify": "handle_pair_verify",
            "/pairings": "handle_pairings",
            "/resource": "handle_resource",
        },
        "GET": {
            "/accessories": "handle_accessories",
            "/characteristics": "handle_get_characteristics",
        },
        "PUT": {
            "/characteristics": "handle_set_characteristics",
        },
    }

    PAIRING_RESPONSE_TYPE = "application/pairing+tlv8"
    JSON_RESPONSE_TYPE = "application/hap+json"

    PAIRING_3_SALT = b"Pair-Setup-Encrypt-Salt"
    PAIRING_3_INFO = b"Pair-Setup-Encrypt-Info"
    PAIRING_3_NONCE = _pad_tls_nonce(b"PS-Msg05")

    PAIRING_4_SALT = b"Pair-Setup-Controller-Sign-Salt"
    PAIRING_4_INFO = b"Pair-Setup-Controller-Sign-Info"

    PAIRING_5_SALT = b"Pair-Setup-Accessory-Sign-Salt"
    PAIRING_5_INFO = b"Pair-Setup-Accessory-Sign-Info"
    PAIRING_5_NONCE = _pad_tls_nonce(b"PS-Msg06")

    PVERIFY_1_SALT = b"Pair-Verify-Encrypt-Salt"
    PVERIFY_1_INFO = b"Pair-Verify-Encrypt-Info"
    PVERIFY_1_NONCE = _pad_tls_nonce(b"PV-Msg02")

    PVERIFY_2_NONCE = _pad_tls_nonce(b"PV-Msg03")

    def __init__(self, accessory_handler, client_address):
        """
        @param accessory_handler: An object that controls an accessory's state.
        @type accessory_handler: AccessoryDriver
        """
        self.accessory_handler = accessory_handler
        self.state = self.accessory_handler.state
        self.enc_context = None
        self.client_address = client_address
        self.is_encrypted = False
        self.server_version = "pyhap/" + __version__

        self.path = None
        self.command = None
        self.headers = None
        self.request_body = None

        self.response = None

    def _set_encryption_ctx(
        self, client_public, private_key, public_key, shared_key, pre_session_key
    ):
        """Sets the encryption context.

        The encryption context is generated in pair verify step one and is used to
        create encrypted transported in pair verify step two.

        @param client_public: The client's session public key.
        @type client_public: bytes

        @param private_key: The state's session private key.
        @type private_key: bytes

        @param shared_key: The resulted session key.
        @type shared_key: bytes

        @param pre_session_key: The key used during session negotiation
            (pair verify one and two).
        @type pre_session_key: bytes
        """
        self.enc_context = {
            "client_public": client_public,
            "private_key": private_key,
            "public_key": public_key,
            "shared_key": shared_key,
            "pre_session_key": pre_session_key,
        }

    def send_response(self, code, message=None):
        """Add the response header to the headers buffer and log the
        response code.
        Does not add Server or Date
        """
        self.response.status_code = code
        self.response.reason = message or "OK"

    def send_header(self, header, value):
        """Add the response header to the headers buffer."""
        self.response.headers.append((header, value))

    def end_response(self, bytesdata):
        """Combines adding a length header and actually sending the data."""
        self.response.body = bytesdata

    def dispatch(self, request, body=None):
        """Dispatch the request to the appropriate handler method."""
        self.path = request.target.decode()
        self.command = request.method.decode()
        self.headers = {k.decode(): v.decode() for k, v in request.headers}
        self.request_body = body
        response = HAPResponse()
        self.response = response

        logger.debug(
            "Request %s from address '%s' for path '%s': %s",
            self.command,
            self.client_address,
            self.path,
            self.headers,
        )

        path = urlparse(self.path).path
        assert path in self.HANDLERS[self.command]
        try:
            getattr(self, self.HANDLERS[self.command][path])()
        except NotAllowedInStateException:
            self.send_response_with_status(
                403, HAP_SERVER_STATUS.INSUFFICIENT_AUTHORIZATION
            )
        except UnprivilegedRequestException:
            self.send_response_with_status(
                401, HAP_SERVER_STATUS.INSUFFICIENT_PRIVILEGES
            )
        except TimeoutException:
            self.send_response_with_status(500, HAP_SERVER_STATUS.OPERATION_TIMED_OUT)
        except Exception:  # pylint: disable=broad-except
            logger.exception("Failed to process request for: %s", path)
            self.send_response_with_status(
                500, HAP_SERVER_STATUS.SERVICE_COMMUNICATION_FAILURE
            )

        self.response = None
        return response

    def send_response_with_status(self, http_code, hap_server_status):
        """Send a generic HAP status response."""
        self.send_response(http_code)
        self.send_header("Content-Type", self.JSON_RESPONSE_TYPE)
        self.end_response(json.dumps({"status": hap_server_status}).encode("utf-8"))

    def handle_pairing(self):
        """Handles arbitrary step of the pairing process."""
        if self.state.paired:
            raise NotAllowedInStateException

        tlv_objects = tlv.decode(self.request_body)
        sequence = tlv_objects[HAP_TLV_TAGS.SEQUENCE_NUM]

        if sequence == b"\x01":
            self._pairing_one()
        elif sequence == b"\x03":
            self._pairing_two(tlv_objects)
        elif sequence == b"\x05":
            self._pairing_three(tlv_objects)

    def _pairing_one(self):
        """Send the SRP salt and public key to the client.

        The SRP verifier is created at this step.
        """
        logger.debug("Pairing [1/5]")
        self.accessory_handler.setup_srp_verifier()
        salt, B = self.accessory_handler.srp_verifier.get_challenge()

        data = tlv.encode(
            HAP_TLV_TAGS.SEQUENCE_NUM,
            b"\x02",
            HAP_TLV_TAGS.SALT,
            salt,
            HAP_TLV_TAGS.PUBLIC_KEY,
            long_to_bytes(B),
        )

        self.send_response(200)
        self.send_header("Content-Type", self.PAIRING_RESPONSE_TYPE)
        self.end_response(data)

    def _pairing_two(self, tlv_objects):
        """Obtain the challenge from the client (A) and client's proof that it
        knows the password (M). Verify M and generate the server's proof based on
        A (H_AMK). Send the H_AMK to the client.

        @param tlv_objects: The TLV data received from the client.
        @type tlv_object: dict
        """
        logger.debug("Pairing [2/5]")
        A = tlv_objects[HAP_TLV_TAGS.PUBLIC_KEY]
        M = tlv_objects[HAP_TLV_TAGS.PASSWORD_PROOF]
        verifier = self.accessory_handler.srp_verifier
        verifier.set_A(A)

        hamk = verifier.verify(M)

        if hamk is None:  # Probably the provided pincode was wrong.
            response = tlv.encode(
                HAP_TLV_TAGS.SEQUENCE_NUM,
                b"\x04",
                HAP_TLV_TAGS.ERROR_CODE,
                HAP_OPERATION_CODE.INVALID_REQUEST,
            )
            self.send_response(200)
            self.send_header("Content-Type", self.PAIRING_RESPONSE_TYPE)
            self.end_response(response)
            return

        data = tlv.encode(
            HAP_TLV_TAGS.SEQUENCE_NUM, b"\x04", HAP_TLV_TAGS.PASSWORD_PROOF, hamk
        )
        self.send_response(200)
        self.send_header("Content-Type", self.PAIRING_RESPONSE_TYPE)
        self.end_response(data)

    def _pairing_three(self, tlv_objects):
        """Expand the SRP session key to obtain a new key. Use it to verify and decrypt
            the recieved data. Continue to step four.

        @param tlv_objects: The TLV data received from the client.
        @type tlv_object: dict
        """
        logger.debug("Pairing [3/5]")
        encrypted_data = tlv_objects[HAP_TLV_TAGS.ENCRYPTED_DATA]

        session_key = self.accessory_handler.srp_verifier.get_session_key()
        hkdf_enc_key = hap_hkdf(
            long_to_bytes(session_key), self.PAIRING_3_SALT, self.PAIRING_3_INFO
        )

        cipher = ChaCha20Poly1305(hkdf_enc_key)
        decrypted_data = cipher.decrypt(
            self.PAIRING_3_NONCE, bytes(encrypted_data), b""
        )
        assert decrypted_data is not None

        dec_tlv_objects = tlv.decode(bytes(decrypted_data))
        client_username = dec_tlv_objects[HAP_TLV_TAGS.USERNAME]
        client_ltpk = dec_tlv_objects[HAP_TLV_TAGS.PUBLIC_KEY]
        client_proof = dec_tlv_objects[HAP_TLV_TAGS.PROOF]

        self._pairing_four(client_username, client_ltpk, client_proof, hkdf_enc_key)

    def _pairing_four(self, client_username, client_ltpk, client_proof, encryption_key):
        """Expand the SRP session key to obtain a new key.
            Use it to verify that the client's proof of the private key. Continue to
            step five.

        @param client_username: The client's username.
        @type client_username: bytes.

        @param client_ltpk: The client's public key.
        @type client_ltpk: bytes

        @param client_proof: The client's proof of password.
        @type client_proof: bytes

        @param encryption_key: The encryption key for this step.
        @type encryption_key: bytes
        """
        logger.debug("Pairing [4/5]")
        session_key = self.accessory_handler.srp_verifier.get_session_key()
        output_key = hap_hkdf(
            long_to_bytes(session_key), self.PAIRING_4_SALT, self.PAIRING_4_INFO
        )

        data = output_key + client_username + client_ltpk
        verifying_key = ed25519.VerifyingKey(client_ltpk)

        try:
            verifying_key.verify(client_proof, data)
        except ed25519.BadSignatureError:
            logger.error("Bad signature, abort.")
            raise

        self._pairing_five(client_username, client_ltpk, encryption_key)

    def _pairing_five(self, client_username, client_ltpk, encryption_key):
        """At that point we know the client has the accessory password and has a valid key
        pair. Add it as a pair and send a sever proof.

        Parameters are as for _pairing_four.
        """
        logger.debug("Pairing [5/5]")
        session_key = self.accessory_handler.srp_verifier.get_session_key()
        output_key = hap_hkdf(
            long_to_bytes(session_key), self.PAIRING_5_SALT, self.PAIRING_5_INFO
        )

        server_public = self.state.public_key.to_bytes()
        mac = self.state.mac.encode()

        material = output_key + mac + server_public
        private_key = self.state.private_key
        server_proof = private_key.sign(material)

        message = tlv.encode(
            HAP_TLV_TAGS.USERNAME,
            mac,
            HAP_TLV_TAGS.PUBLIC_KEY,
            server_public,
            HAP_TLV_TAGS.PROOF,
            server_proof,
        )

        cipher = ChaCha20Poly1305(encryption_key)
        aead_message = bytes(cipher.encrypt(self.PAIRING_5_NONCE, bytes(message), b""))

        client_uuid = uuid.UUID(str(client_username, "utf-8"))
        should_confirm = self.accessory_handler.pair(client_uuid, client_ltpk)

        if not should_confirm:
            self.send_response_with_status(
                500, HAP_SERVER_STATUS.INVALID_VALUE_IN_REQUEST
            )
            return

        tlv_data = tlv.encode(
            HAP_TLV_TAGS.SEQUENCE_NUM,
            b"\x06",
            HAP_TLV_TAGS.ENCRYPTED_DATA,
            aead_message,
        )
        self.send_response(200)
        self.send_header("Content-Type", self.PAIRING_RESPONSE_TYPE)
        self.end_response(tlv_data)

    def handle_pair_verify(self):
        """Handles arbitrary step of the pair verify process.

        Pair verify is session negotiation.
        """
        if not self.state.paired:
            raise NotAllowedInStateException

        tlv_objects = tlv.decode(self.request_body)
        sequence = tlv_objects[HAP_TLV_TAGS.SEQUENCE_NUM]
        if sequence == b"\x01":
            self._pair_verify_one(tlv_objects)
        elif sequence == b"\x03":
            self._pair_verify_two(tlv_objects)
        else:
            raise ValueError(
                "Unknown pairing sequence of %s during pair verify" % (sequence)
            )

    def _pair_verify_one(self, tlv_objects):
        """Generate new session key pair and send a proof to the client.

        @param tlv_objects: The TLV data received from the client.
        @type tlv_object: dict
        """
        logger.debug("Pair verify [1/2].")
        client_public = tlv_objects[HAP_TLV_TAGS.PUBLIC_KEY]

        private_key = curve25519.Private()
        public_key = private_key.get_public()
        shared_key = private_key.get_shared_key(
            curve25519.Public(client_public),
            # Key is hashed before being returned, we don't want it; This fixes that.
            lambda x: x,
        )

        mac = self.state.mac.encode()
        material = public_key.serialize() + mac + client_public
        server_proof = self.state.private_key.sign(material)

        output_key = hap_hkdf(shared_key, self.PVERIFY_1_SALT, self.PVERIFY_1_INFO)

        self._set_encryption_ctx(
            client_public, private_key, public_key, shared_key, output_key
        )

        message = tlv.encode(
            HAP_TLV_TAGS.USERNAME, mac, HAP_TLV_TAGS.PROOF, server_proof
        )

        cipher = ChaCha20Poly1305(output_key)
        aead_message = bytes(cipher.encrypt(self.PVERIFY_1_NONCE, bytes(message), b""))
        data = tlv.encode(
            HAP_TLV_TAGS.SEQUENCE_NUM,
            b"\x02",
            HAP_TLV_TAGS.ENCRYPTED_DATA,
            aead_message,
            HAP_TLV_TAGS.PUBLIC_KEY,
            public_key.serialize(),
        )
        self.send_response(200)
        self.send_header("Content-Type", self.PAIRING_RESPONSE_TYPE)
        self.end_response(data)

    def _pair_verify_two(self, tlv_objects):
        """Verify the client proof and upgrade to encrypted transport.

        @param tlv_objects: The TLV data received from the client.
        @type tlv_object: dict
        """
        logger.debug("Pair verify [2/2]")
        encrypted_data = tlv_objects[HAP_TLV_TAGS.ENCRYPTED_DATA]
        cipher = ChaCha20Poly1305(self.enc_context["pre_session_key"])
        decrypted_data = cipher.decrypt(
            self.PVERIFY_2_NONCE, bytes(encrypted_data), b""
        )
        assert decrypted_data is not None  # TODO:

        dec_tlv_objects = tlv.decode(bytes(decrypted_data))
        client_username = dec_tlv_objects[HAP_TLV_TAGS.USERNAME]
        material = (
            self.enc_context["client_public"]
            + client_username
            + self.enc_context["public_key"].serialize()
        )

        client_uuid = uuid.UUID(str(client_username, "ascii"))
        perm_client_public = self.state.paired_clients.get(client_uuid)
        if perm_client_public is None:
            logger.debug(
                "Client %s attempted pair verify without being paired first.",
                client_uuid,
            )
            self.send_response(200)
            self.send_header("Content-Type", self.PAIRING_RESPONSE_TYPE)
            data = tlv.encode(
                HAP_TLV_TAGS.ERROR_CODE, HAP_OPERATION_CODE.INVALID_REQUEST
            )
            self.end_response(data)
            return

        verifying_key = ed25519.VerifyingKey(perm_client_public)
        try:
            verifying_key.verify(dec_tlv_objects[HAP_TLV_TAGS.PROOF], material)
        except ed25519.BadSignatureError:
            logger.error("Bad signature, abort.")
            self.send_response(200)
            self.send_header("Content-Type", self.PAIRING_RESPONSE_TYPE)
            data = tlv.encode(
                HAP_TLV_TAGS.ERROR_CODE, HAP_OPERATION_CODE.INVALID_REQUEST
            )
            self.end_response(data)
            return

        logger.debug(
            "Pair verify with client '%s' completed. Switching to "
            "encrypted transport.",
            self.client_address,
        )

        data = tlv.encode(HAP_TLV_TAGS.SEQUENCE_NUM, b"\x04")
        self.send_response(200)
        self.send_header("Content-Type", self.PAIRING_RESPONSE_TYPE)
        self.end_response(data)

        self.response.shared_key = self.enc_context["shared_key"]
        self.is_encrypted = True
        del self.enc_context

    def handle_accessories(self):
        """Handles a client request to get the accessories."""
        if not self.is_encrypted:
            raise UnprivilegedRequestException

        hap_rep = self.accessory_handler.get_accessories()
        data = json.dumps(hap_rep).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", self.JSON_RESPONSE_TYPE)
        self.end_response(data)

    def handle_get_characteristics(self):
        """Handles a client request to get certain characteristics."""
        if not self.is_encrypted:
            raise UnprivilegedRequestException

        # Check that char exists and ...
        params = parse_qs(urlparse(self.path).query)
        chars = self.accessory_handler.get_characteristics(params["id"][0].split(","))

        data = json.dumps(chars).encode("utf-8")
        self.send_response(207)
        self.send_header("Content-Type", self.JSON_RESPONSE_TYPE)
        self.end_response(data)

    def handle_set_characteristics(self):
        """Handles a client request to update certain characteristics."""
        if not self.is_encrypted:
            logger.warning(
                "Attempt to access unauthorised content from %s", self.client_address
            )
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.end_response(b"")

        requested_chars = json.loads(self.request_body.decode("utf-8"))
        logger.debug("Set characteristics content: %s", requested_chars)

        # TODO: Outline how chars return errors on set_chars.
        try:
            self.accessory_handler.set_characteristics(
                requested_chars, self.client_address
            )
        except Exception as e:  # pylint: disable=broad-except
            logger.exception("Exception in set_characteristics: %s", e)
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.end_response(b"")
        else:
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_response(b"")

    def handle_pairings(self):
        """Handles a client request to update or remove a pairing."""
        if not self.is_encrypted:
            raise UnprivilegedRequestException

        tlv_objects = tlv.decode(self.request_body)
        request_type = tlv_objects[HAP_TLV_TAGS.REQUEST_TYPE][0]
        if request_type == 3:
            self._handle_add_pairing(tlv_objects)
        elif request_type == 4:
            self._handle_remove_pairing(tlv_objects)
        else:
            raise ValueError(
                "Unknown pairing request type of %s during pair verify" % (request_type)
            )

    def _handle_add_pairing(self, tlv_objects):
        """Update client information."""
        logger.debug("Adding client pairing.")
        client_username = tlv_objects[HAP_TLV_TAGS.USERNAME]
        client_public = tlv_objects[HAP_TLV_TAGS.PUBLIC_KEY]
        client_uuid = uuid.UUID(str(client_username, "utf-8"))
        should_confirm = self.accessory_handler.pair(client_uuid, client_public)
        if not should_confirm:
            self.send_response_with_status(
                500, HAP_SERVER_STATUS.INVALID_VALUE_IN_REQUEST
            )
            return

        data = tlv.encode(HAP_TLV_TAGS.SEQUENCE_NUM, b"\x02")
        self.send_response(200)
        self.send_header("Content-Type", self.PAIRING_RESPONSE_TYPE)
        self.end_response(data)

        # Avoid updating the announcement until
        # after the response is sent as homekit will
        # drop the connection and fail to pair if it
        # sees the accessory is now paired as it doesn't
        # know that it was the one doing the pairing.
        self.accessory_handler.finish_pair()

    def _handle_remove_pairing(self, tlv_objects):
        """Remove pairing with the client."""
        logger.debug("Removing client pairing.")
        client_username = tlv_objects[HAP_TLV_TAGS.USERNAME]
        client_uuid = uuid.UUID(str(client_username, "utf-8"))
        self.accessory_handler.unpair(client_uuid)

        data = tlv.encode(HAP_TLV_TAGS.SEQUENCE_NUM, b"\x02")
        self.send_response(200)
        self.send_header("Content-Type", self.PAIRING_RESPONSE_TYPE)
        self.end_response(data)

        # Avoid updating the announcement until
        # after the response is sent.
        self.accessory_handler.finish_pair()

    def handle_resource(self):
        """Get a snapshot from the camera."""
        image_size = json.loads(self.request_body.decode("utf-8"))
        loop = asyncio.get_event_loop()
        if hasattr(self.accessory_handler.accessory, "async_get_snapshot"):
            coro = self.accessory_handler.accessory.async_get_snapshot(image_size)
        elif hasattr(self.accessory_handler.accessory, "get_snapshot"):
            coro = asyncio.wait_for(
                loop.run_in_executor(
                    None, self.accessory_handler.accessory.get_snapshot, image_size
                ),
                SNAPSHOT_TIMEOUT,
            )
        else:
            raise ValueError(
                "Got a request for snapshot, but the Accessory "
                'does not define a "get_snapshot" or "async_get_snapshot" method'
            )

        task = asyncio.create_task(coro)
        self.send_response(200)
        self.send_header("Content-Type", "image/jpeg")
        self.response.task = task

    async def async_get_snapshot(self, image_size):
        loop = asyncio.get_event_loop()
        return await asyncio.wait_for(
            loop.run_in_executor(
                None, self.accessory_handler.accessory.get_snapshot, image_size
            ),
            SNAPSHOT_TIMEOUT,
        )


class HAPServerProtocol(asyncio.Protocol):
    """A asyncio.Protocol implementing the HAP protocol."""

    MAX_BLOCK_LENGTH = 0x400
    LENGTH_LENGTH = 2

    CIPHER_SALT = b"Control-Salt"
    OUT_CIPHER_INFO = b"Control-Read-Encryption-Key"
    IN_CIPHER_INFO = b"Control-Write-Encryption-Key"

    def __init__(self, loop, connections, accessory_handler) -> None:
        self.loop = loop
        self.conn = h11.Connection(h11.SERVER)
        self.connections = connections
        self.accessory_handler = accessory_handler
        self.hap_server_handler = None
        self.peername = None

        self.request = None
        self.response = None

        self.shared_key = None
        self.out_count = 0
        self.in_count = 0
        self.out_cipher = None
        self.in_cipher = None

        self.curr_encrypted = b""  # Encrypted buffer

    def _set_ciphers(self) -> None:
        """Generate out/inbound encryption keys and initialise respective ciphers."""
        outgoing_key = hap_hkdf(self.shared_key, self.CIPHER_SALT, self.OUT_CIPHER_INFO)
        self.out_cipher = ChaCha20Poly1305(outgoing_key)

        incoming_key = hap_hkdf(self.shared_key, self.CIPHER_SALT, self.IN_CIPHER_INFO)
        self.in_cipher = ChaCha20Poly1305(incoming_key)

    def decrypt_buffer(self) -> str:
        """Receive up to buflen bytes.

        The received full cipher blocks are decrypted and returned and partial cipher
        blocks are buffered locally.
        """
        result = b""

        # If we do not have a partial decrypted block
        # read the next one
        while len(self.curr_encrypted) > self.LENGTH_LENGTH:
            block_length_bytes = self.curr_encrypted[: self.LENGTH_LENGTH]
            block_size = struct.unpack("H", block_length_bytes)[0]
            data_size = self.LENGTH_LENGTH + block_size + HAP_CRYPTO.TAG_LENGTH

            if len(self.curr_encrypted) < data_size:
                return result

            if len(self.curr_encrypted) >= data_size:
                nonce = _pad_tls_nonce(struct.pack("Q", self.in_count))
                result += self.in_cipher.decrypt(
                    nonce,
                    bytes(
                        self.curr_encrypted[
                            self.LENGTH_LENGTH : self.LENGTH_LENGTH + data_size
                        ]
                    ),
                    block_length_bytes,
                )
                self.in_count += 1
                self.curr_encrypted = self.curr_encrypted[data_size:]
            else:
                return result

        return result

    def connection_lost(self, exc: Exception) -> None:
        """Handle connection lost."""
        logger.debug("%s: Connection lost: %s", self.peername, exc)
        self.close()

    def connection_made(self, transport: asyncio.Transport) -> None:
        peername = transport.get_extra_info("peername")
        logger.info("%s: Connection made", peername)
        self.transport = transport
        self.peername = peername
        self.connections[peername] = self
        self.hap_server_handler = HAPServerHandler(self.accessory_handler, peername)

    def write(self, data: bytes) -> None:
        if self.shared_key:
            self._write_encrypted(data)
        else:
            logger.debug("%s: Send unencrypted: %s", self.peername, data)
            self.transport.write(data)

    def _write_encrypted(self, data: bytes) -> None:
        """Encrypt and send the given data."""
        result = b""
        offset = 0
        total = len(data)
        while offset < total:
            length = min(total - offset, self.MAX_BLOCK_LENGTH)
            length_bytes = struct.pack("H", length)
            block = bytes(data[offset : offset + length])
            nonce = _pad_tls_nonce(struct.pack("Q", self.out_count))
            ciphertext = length_bytes + self.out_cipher.encrypt(
                nonce, block, length_bytes
            )
            offset += length
            self.out_count += 1
            result += ciphertext
        logger.debug("%s: Send encrypted: %s", self.peername, data)
        self.transport.write(result)

    def close(self) -> None:
        """Remove the connection and close the transport."""
        if self.peername in self.connections:
            del self.connections[self.peername]
        self.transport.close()

    def send_response(self, response: HAPResponse) -> None:
        """Send a HAPResponse object."""
        self.write(
            self.conn.send(
                h11.Response(
                    status_code=response.status_code,
                    reason=response.reason,
                    headers=response.headers,
                )
            )
            + self.conn.send(h11.Data(data=response.body))
            + self.conn.send(h11.EndOfMessage())
        )

    def _handle_response_ready(self, task: asyncio.Task) -> None:
        """Handle delayed response."""
        response = self.response
        self.response = None
        response.body = task.result()
        self.send_response(response)

    def data_received(self, data: bytes) -> None:
        """Process new data from the socket."""
        if self.shared_key:
            self.curr_encrypted += data
            unencrypted_data = self.decrypt_buffer()
            if unencrypted_data == b"":
                logger.debug("No decryptable data")
                return
            logger.debug("%s: Recv decrypted: %s", self.peername, unencrypted_data)
            self.conn.receive_data(unencrypted_data)
        else:
            self.conn.receive_data(data)
            logger.debug("%s: Recv unencrypted: %s", self.peername, data)

        while self._process_one_event():
            pass

    def _process_one_event(self) -> bool:
        """Process one http event."""
        event = self.conn.next_event()

        logger.debug("%s: h11 Event: %s", self.peername, event)

        if self.conn.our_state is h11.MUST_CLOSE:
            return self._handle_invalid_conn_state("connection state is must close")

        elif event is h11.NEED_DATA:
            return False

        elif event is h11.PAUSED:
            if self.request:
                return self._handle_invalid_conn_state(
                    "paused when a request is in progress"
                )
            self.conn.start_next_cycle()
            return True

        elif type(event) is h11.Request:
            self.request = event

            if event.method in {b"PUT", b"POST"}:
                return True

            elif event.method == b"GET":
                return self._process_response(
                    self.hap_server_handler.dispatch(self.request)
                )

        elif type(event) is h11.Data:
            return self._process_response(
                self.hap_server_handler.dispatch(self.request, bytes(event.data))
            )

        elif type(event) is h11.EndOfMessage:
            self.request = None
            return True

    def _process_response(self, response) -> None:
        """Process a response from the handler."""
        if response.task:
            # If there is a task pending we will schedule
            # the response later
            self.response = response
            response.task.add_done_callback(self._handle_response_ready)
        else:
            self.send_response(response)

        # If we get a shared key, upgrade to encrypted
        if response.shared_key:
            self.shared_key = response.shared_key
            self._set_ciphers()

        return True

    def _handle_invalid_conn_state(self, message):
        """Log invalid state and close."""
        logger.debug(
            "%s: Invalid state: %s: close the client socket",
            message,
            self.peername,
        )
        self.close()
        return False


class HAPServer:
    """Point of contact for HAP clients.

    The HAPServer handles all incoming client requests (e.g. pair) and also handles
    communication from Accessories to clients (value changes). The outbound communication
    is something like HTTP push.

    @note: Client requests responses as well as outgoing event notifications happen through
    the same socket for the same client. This introduces a race condition - an Accessory
    decides to push a change in current temperature, while in the same time the HAP client
    decides to query the state of the Accessory. To overcome this the HAPSocket class
    implements exclusive access to the send methods.
    """

    EVENT_MSG_STUB = (
        b"EVENT/1.0 200 OK\r\n"
        b"Content-Type: application/hap+json\r\n"
        b"Content-Length: "
    )

    @classmethod
    def create_hap_event(cls, bytesdata):
        """Creates a HAP HTTP EVENT response for the given data.

        @param data: Payload of the request.
        @type data: bytes
        """
        return (
            cls.EVENT_MSG_STUB
            + str(len(bytesdata)).encode("utf-8")
            + b"\r\n" * 2
            + bytesdata
        )

    def __init__(self, addr_port, accessory_handler):
        """Create a HAP Server."""
        self._addr_port = addr_port
        self.connections = {}  # (address, port): socket
        self.accessory_handler = accessory_handler
        self.server = None
        self._serve_task = None

    async def async_start(self):
        """Start the http-hap server."""
        loop = asyncio.get_running_loop()

        self.server = await loop.create_server(
            lambda: HAPServerProtocol(loop, self.connections, self.accessory_handler),
            self._addr_port[0],
            self._addr_port[1],
        )
        self._serve_task = asyncio.create_task(self.server.serve_forever())

    def stop(self):
        """Stop the server."""
        self.server.close()
        for hap_server_protocol in list(self.connections.values()):
            hap_server_protocol.close()
        self.connections.clear()
        self._serve_task.cancel()

    def push_event(self, bytesdata, client_addr):
        """Send an event to the current connection with the provided data.

        :param bytesdata: The data to send.
        :type bytesdata: bytes

        :param client_addr: A client (address, port) tuple to which to send the data.
        :type client_addr: tuple <str, int>

        :return: True if sending was successful, False otherwise.
        :rtype: bool
        """
        hap_server_protocol = self.connections.get(client_addr)
        if hap_server_protocol is None:
            logger.debug("No socket for %s", client_addr)
            return False
        hap_server_protocol.write(self.create_hap_event(bytesdata))
        return True
