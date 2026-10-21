"""Run the durable scheduler and notification outbox in one supervised worker service."""

import asyncio
import logging
import os
import signal

from services.api.notifications import run_worker as run_notification_worker
from services.api.scheduler import run_worker as run_scheduler_worker


async def run_worker(stop_event: asyncio.Event | None = None) -> None:
    stop_event = stop_event or asyncio.Event()
    workers = [
        asyncio.create_task(run_scheduler_worker(), name="cloudsentinel-scheduler"),
        asyncio.create_task(run_notification_worker(), name="cloudsentinel-notifications"),
    ]
    stopping = asyncio.create_task(stop_event.wait(), name="cloudsentinel-stop-signal")
    try:
        done, _ = await asyncio.wait([*workers, stopping], return_when=asyncio.FIRST_COMPLETED)
        if stopping not in done:
            # Surface an unexpected worker exit so the process supervisor restarts it.
            for task in done:
                task.result()
    finally:
        stopping.cancel()
        for task in workers:
            if not task.done():
                task.cancel()
        await asyncio.gather(stopping, *workers, return_exceptions=True)


async def serve() -> None:
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()
    installed: list[signal.Signals] = []
    for stop_signal in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(stop_signal, stop_event.set)
            installed.append(stop_signal)
        except (NotImplementedError, RuntimeError):
            # ProactorEventLoop (Windows) does not implement add_signal_handler.
            signal.signal(
                stop_signal,
                lambda _signum, _frame, event=stop_event, event_loop=loop:
                    event_loop.call_soon_threadsafe(event.set),
            )
    try:
        await run_worker(stop_event)
    finally:
        for stop_signal in installed:
            loop.remove_signal_handler(stop_signal)


if __name__ == "__main__":
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        logging.getLogger(__name__).info("CloudSentinel worker stopped.")
