"""Account-mode Baichuan refusal must not discard authenticated HTTP access."""

import unittest
from unittest.mock import AsyncMock

from reolink_aio.api import Host
from reolink_aio.http_crypto import HttpCrypto
from reolink_aio.exceptions import CredentialsInvalidError, LoginAccountDeviceError


class HttpOnlyAccountTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.host = Host(
            "127.0.0.1", "test-user", "test-password", port=443, use_https=True
        )

    async def asyncTearDown(self):
        if not self.host._aiohttp_session.closed:
            await self.host._aiohttp_session.close()

    async def test_authenticated_digest_can_use_http_only(self):
        self.host._http_crypto = HttpCrypto(
            "test-user", "test-password", "nonce", "cnonce"
        )  # Fixture: established encrypted HTTP session.
        self.host.baichuan.send = AsyncMock(
            side_effect=LoginAccountDeviceError("fixture account-mode denial")
        )
        self.host._stream_channels = [0, 1]
        await self.host.baichuan.get_host_data()
        self.host.baichuan.send.assert_awaited_once_with(cmd_id=199)
        self.assertEqual(
            self.host.baichuan.capabilities,
            {None: {None: set()}, 0: {None: set()}, 1: {None: set()}},
        )

    async def test_unauthenticated_account_device_still_rejected(self):
        self.host.baichuan.send = AsyncMock(
            side_effect=LoginAccountDeviceError("fixture account-mode denial")
        )
        with self.assertRaises(LoginAccountDeviceError):
            await self.host.baichuan.get_host_data()

    async def test_invalid_credentials_never_suppressed(self):
        self.host._http_crypto = HttpCrypto(
            "test-user", "test-password", "nonce", "cnonce"
        )
        self.host.baichuan.send = AsyncMock(
            side_effect=CredentialsInvalidError("fixture invalid credentials")
        )
        with self.assertRaises(CredentialsInvalidError):
            await self.host.baichuan.get_host_data()


if __name__ == "__main__":
    unittest.main()
