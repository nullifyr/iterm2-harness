#!/usr/bin/env python3
"""AutoLaunch entrypoint; importing it never starts the server."""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))  # Resolve package correctly through an AutoLaunch symlink.


def run():
    from iterm2_harness import __version__
    if "--version" in sys.argv:
        print(__version__)
        return
    if sys.version_info < (3, 9):
        raise SystemExit("iTerm2 Harness 2.1 requires Python 3.9+; update the iTerm2 Python runtime")
    from iterm2_harness.security import load_config
    config = load_config(ROOT)
    if "--check-config" in sys.argv:
        print("Configuration valid; bind %s:%s" % (config["host"], config["port"]))
        return
    import asyncio
    import iterm2
    from iterm2_harness.iterm import Adapter
    from iterm2_harness.prompt import ask
    from iterm2_harness.server import Server
    from iterm2_harness.state import EventLog, Observations

    async def main(connection):
        events = EventLog()
        observations = Observations(events)
        adapter = Adapter(connection, events, observations)
        service = Server(config, adapter, events, observations, ask, ROOT)
        listener, tasks = None, []
        try:
            await adapter.start()
            # Stable port, no silent fallback that leaves clients on an orphan.
            listener = await asyncio.start_server(service.handle_client, config["host"], config["port"], limit=8194)
            service.audit("server.start", version=__version__, epoch=events.epoch)
            tasks = [asyncio.create_task(listener.serve_forever()),
                     asyncio.create_task(adapter.supervise(service.stop))]
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        finally:
            service.stop.set()
            adapter.alive = False
            if listener:
                listener.close()
                await listener.wait_closed()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await service.close_clients()
            await adapter.close()
        if service.reload_requested:
            os.execv(sys.executable, [sys.executable, str(ROOT / "iterm2-harness.py")])

    # main owns all serving tasks and returns only after cleanup. Public health
    # probes bound disconnection detection; run_forever by itself is not cleanup.
    iterm2.run_until_complete(main)


if __name__ == "__main__":
    run()
