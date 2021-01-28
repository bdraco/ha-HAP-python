"""This module implements the communication of HAP.

The HAPServerHandler manages the state of the connection and handles incoming requests.
The HAPServerProtocol is a protocol implementation that manages the "TLS" of the connection.
"""
import asyncio
import logging
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import h11

from pyhap.const import __version__

from .hap_crypto import HAP_CRYPTO, hap_hkdf, pad_tls_nonce
from .hap_handler import HAPResponse, HAPServerHandler

logger = logging.getLogger(__name__)


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
        self.transport = None

        self.request = None
        self.response = None

        self.shared_key = None
        self.out_count = 0
        self.in_count = 0
        self.out_cipher = None
        self.in_cipher = None

        self._incoming_buffer = bytearray()  # Encrypted buffer

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
        while len(self._incoming_buffer) > self.LENGTH_LENGTH:
            block_length_bytes = self._incoming_buffer[: self.LENGTH_LENGTH]
            block_size = struct.unpack("H", block_length_bytes)[0]
            block_size_with_length = (
                self.LENGTH_LENGTH + block_size + HAP_CRYPTO.TAG_LENGTH
            )

            if len(self._incoming_buffer) >= block_size_with_length:

                # Trim off the length
                del self._incoming_buffer[: self.LENGTH_LENGTH]

                data_size = block_size + HAP_CRYPTO.TAG_LENGTH
                nonce = pad_tls_nonce(struct.pack("Q", self.in_count))

                try:
                    result += self.in_cipher.decrypt(
                        nonce,
                        bytes(self._incoming_buffer[:data_size]),
                        bytes(block_length_bytes),
                    )
                except InvalidTag:
                    logger.debug(
                        "%s: Decrypt failed, closing connection",
                        self.peername,
                    )
                    self.close()
                    return result

                self.in_count += 1

                # Now trim out the decrypted data
                del self._incoming_buffer[:data_size]
            else:
                return result

        return result

    def connection_lost(self, exc: Exception) -> None:
        """Handle connection lost."""
        logger.debug("%s: Connection lost: %s", self.peername, exc)
        self.close()

    def connection_made(self, transport: asyncio.Transport) -> None:
        """Handle incoming connection."""
        peername = transport.get_extra_info("peername")
        logger.info("%s: Connection made", peername)
        self.transport = transport
        self.peername = peername
        self.connections[peername] = self
        self.hap_server_handler = HAPServerHandler(self.accessory_handler, peername)

    def write(self, data: bytes) -> None:
        """Write data to the client."""
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
            nonce = pad_tls_nonce(struct.pack("Q", self.out_count))
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
            self._incoming_buffer += data
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

        if event is h11.NEED_DATA:
            return False

        if event is h11.PAUSED:
            if self.request:
                return self._handle_invalid_conn_state(
                    "paused when a request is in progress"
                )
            self.conn.start_next_cycle()
            return True

        if isinstance(event, h11.Request):
            self.request = event

            if event.method in {b"PUT", b"POST"}:
                return True

            if event.method == b"GET":
                return self._process_response(
                    self.hap_server_handler.dispatch(self.request)
                )

            return self._handle_invalid_conn_state(
                "No handler for method {}".format(event.method.decode())
            )

        if isinstance(event, h11.Data):
            return self._process_response(
                self.hap_server_handler.dispatch(self.request, bytes(event.data))
            )

        if isinstance(event, h11.EndOfMessage):
            self.request = None
            return True

        return self._handle_invalid_conn_state("Unexpected event: {}".format(event))

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
