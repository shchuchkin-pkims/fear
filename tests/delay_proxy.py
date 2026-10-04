#!/usr/bin/env python3
"""
TCP-прокси, задерживающий ответы сервера: как Wi-Fi до ретранслятора, только
предсказуемо. Запросы клиента идут сразу, ответы - через DELAY_MS, порядок
сохраняется.

    delay_proxy.py LISTEN_PORT TARGET_PORT DELAY_MS
"""
import asyncio
import sys

LISTEN, TARGET, DELAY = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]) / 1000.0


async def pipe(reader, writer, delay):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            if delay:
                await asyncio.sleep(delay)
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        writer.close()


async def handle(client_reader, client_writer):
    server_reader, server_writer = await asyncio.open_connection("127.0.0.1", TARGET)
    await asyncio.gather(pipe(client_reader, server_writer, 0),
                         pipe(server_reader, client_writer, DELAY))


async def main():
    server = await asyncio.start_server(handle, "127.0.0.1", LISTEN)
    async with server:
        await server.serve_forever()


asyncio.run(main())
