"""Independent client for the external_ws_incoming Rust test."""
import asyncio
import os
from websockets.asyncio.client import connect
from websockets.exceptions import InvalidStatus

async def main():
    addr = os.environ.get("H3X_WS_LISTEN", "127.0.0.1:8766")
    options = dict(subprotocols=["h3x-test"], origin="https://external.example",
                   compression=None, ping_interval=None, proxy=None)
    async with connect(f"ws://{addr}/echo?mode=reverse", **options) as ws:
        assert ws.subprotocol == "h3x-test"
        assert await ws.recv() == "h3-ready"
        print("PASS HTTP/1.1 Upgrade, subprotocol, H3 greeting", flush=True)
        for message in ["external client — 你好", bytes(range(256)),
                        bytes(n % 251 for n in range(256 * 1024))]:
            await ws.send(message)
            assert await ws.recv() == message
        print("PASS UTF-8 text, binary, 256 KiB message", flush=True)
        await ws.send(["frag-", "mented"])
        assert await ws.recv() == "frag-mented"
        print("PASS masked fragmentation", flush=True)
        pong = await ws.ping(b"reverse-ping")
        await asyncio.wait_for(pong, timeout=5)
        print("PASS Ping/Pong", flush=True)
        await ws.close(code=1000, reason="reverse done")
        assert ws.close_code == 1000
        print("PASS Close handshake", flush=True)
    try:
        async with connect(f"ws://{addr}/reject", **options):
            raise AssertionError("rejected request upgraded")
    except InvalidStatus as error:
        assert error.response.status_code == 403
        assert error.response.body == b"denied"
        print("PASS H3 rejection preserved as HTTP 403 + body", flush=True)

asyncio.run(main())
