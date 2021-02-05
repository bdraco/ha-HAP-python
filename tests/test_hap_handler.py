"""Tests for the HAPServerHandler."""


from pyhap import hap_handler
from pyhap.accessory import Accessory
import pyhap.tlv as tlv


def test_list_pairings(driver):
    """Verify an encrypted list pairings request."""
    driver.add_accessory(Accessory(driver, "TestAcc"))

    handler = hap_handler.HAPServerHandler(driver, "peername")
    handler.is_encrypted = True
    driver.pair(
        "7d0d1ee9-46fe-4a56-a115-69df3f6860c1",
        b"\x99\x98d%\x8c\xf6h\x06\xfa\x85\x9f\x90\x82\xf2\xe8\x18\x9f\xf8\xc75\x1f>~\xc32\xc1OC\x13\xbfH\xad",
    )

    response = hap_handler.HAPResponse()
    handler.response = response
    handler.request_body = tlv.encode(hap_handler.HAP_TLV_TAGS.REQUEST_TYPE, b"\x05")
    handler.handle_pairings()

    assert (
        response.body
        == b"\x06\x01\x02\x01$7d0d1ee9-46fe-4a56-a115-69df3f6860c1\x03 \x99\x98d%\x8c\xf6h\x06\xfa\x85\x9f\x90\x82\xf2\xe8\x18\x9f\xf8\xc75\x1f>~\xc32\xc1OC\x13\xbfH\xad\x0b\x01\x01"
    )
