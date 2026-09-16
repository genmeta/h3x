"""Independent echo peer for external_ws_echo; requires Python websockets."""
import asyncio
import os
from websockets.asyncio.server import serve

async def echo(ws):
    await ws.send("ready")
    async for message in ws:
        print(f"echo {type(message).__name__}: {len(message)}", flush=True)
        await ws.send(message)

async def main():
    port = int(os.environ.get("H3X_WS_PORT", "8765"))
    async with serve(echo, "127.0.0.1", port, subprotocols=["h3x-test"],
                     compression=None, ping_interval=None) as server:
        print(f"READY ws://127.0.0.1:{port}/echo", flush=True)
        await server.serve_forever()

asyncio.run(main())
