"""Keep a queued request's token paired with its captured crypto session."""

import asyncio
import unittest
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, Mock

import aiohttp

from reolink_aio.api import Host
from reolink_aio.http_crypto import HttpCrypto


class HttpSessionPairingTests(unittest.IsolatedAsyncioTestCase):
    async def test_session_change_while_waiting_for_send_mutex(self):
        host = Host("127.0.0.1", "test-user", "test-password", port=443, use_https=True)
        original_session = host._aiohttp_session
        crypto_a = HttpCrypto("test-user", "test-password", "nonce-a", "cnonce-a")
        crypto_b = HttpCrypto("test-user", "test-password", "nonce-b", "cnonce-b")
        response = SimpleNamespace(
            status=200,
            content_type="image/jpeg",
            read=AsyncMock(return_value=b"fixture-image"),
            release=Mock(),
        )
        transport = SimpleNamespace(closed=False, get=AsyncMock(return_value=response))
        host._aiohttp_session = cast(aiohttp.ClientSession, transport)
        host._login_open_port = AsyncMock()
        host._token = "fixture-session-A"
        host._http_crypto = crypto_a
        params = {"cmd": "Snap", "channel": 0}
        task = None
        try:
            await host._send_mutex.acquire()
            task = asyncio.create_task(host.send_chunk([], params, "image/jpeg", 1))
            await asyncio.sleep(0)
            self.assertEqual(params["token"], "fixture-session-A")
            self.assertFalse(task.done())
            host._token = "fixture-session-B"
            host._http_crypto = crypto_b
            host._send_mutex.release()
            self.assertEqual(await task, b"fixture-image")
            url = transport.get.call_args.kwargs["url"]
            self.assertEqual(url.query["token"], "fixture-session-A")
            encrypted_query = url.raw_query_string.partition("&encrypt=")[2]
            decrypted = crypto_a.decrypt(encrypted_query)
            assert decrypted is not None
            self.assertIn("cmd=Snap", decrypted)
            self.assertIsNone(crypto_b.decrypt(encrypted_query))
        finally:
            if host._send_mutex.locked():
                host._send_mutex.release()
            if task is not None and not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            await original_session.close()


if __name__ == "__main__":
    unittest.main()
