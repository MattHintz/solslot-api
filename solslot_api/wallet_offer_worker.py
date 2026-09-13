"""Private, bounded process jobs for wallet-offer validation.

IPC is generated only by this application and its exact local worker. It is
never a wallet, HTTP, file-upload or provider serialization format. Native Chia
objects have explicit byte reducers so returning an Offer does not re-run its
constructor or discard its evaluated caches.
"""
from __future__ import annotations

import asyncio
import copyreg
import io
import logging
import pickle
import sys
import weakref

from chia.types.blockchain_format.program import Program
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import Coin, CoinSpend, G1Element, G2Element, Program as SerializedProgram

logger = logging.getLogger(__name__)

MAX_IPC_BYTES = 16_000_000
MAX_WORKERS = 2
WORKER_TIMEOUT_SECONDS = 20
_CLASSES = {
    "bundle": WalletSpendBundle, "coin": Coin, "spend": CoinSpend,
    "g1": G1Element, "g2": G2Element, "serialized": SerializedProgram,
    "program": Program,
}
_NAMES = {value: key for key, value in _CLASSES.items()}
_LIMITS = weakref.WeakKeyDictionary()


def _restore_native(name, raw):
    return _CLASSES[name].from_bytes(raw)


def _reduce_native(value):
    return _restore_native, (_NAMES[type(value)], bytes(value))


def _pack_local(value) -> bytes:
    buffer = io.BytesIO()
    encoder = pickle.Pickler(buffer, protocol=5)
    encoder.dispatch_table = copyreg.dispatch_table.copy()
    for cls in _CLASSES.values():
        encoder.dispatch_table[cls] = _reduce_native
    encoder.dump(value)
    result = buffer.getvalue()
    if len(result) > MAX_IPC_BYTES:
        raise ValueError("wallet validation IPC limit exceeded")
    return result


def _unpack_local(raw: bytes):
    # Only bytes received from the private stdin/stdout of our local executable
    # may reach this function; client offers remain ordinary strings inside the
    # locally constructed message and are parsed by wallet_offer_validation.
    if len(raw) > MAX_IPC_BYTES:
        raise ValueError("wallet validation IPC limit exceeded")
    try:
        return pickle.loads(raw)
    except (pickle.UnpicklingError, EOFError, AttributeError, TypeError) as exc:
        raise ValueError("invalid local wallet validation result") from exc


async def _read_bounded(stream) -> bytes:
    result = bytearray()
    while True:
        chunk = await stream.read(min(65536, MAX_IPC_BYTES + 1 - len(result)))
        if not chunk:
            return bytes(result)
        result.extend(chunk)
        if len(result) > MAX_IPC_BYTES:
            raise ValueError("wallet validation worker output limit exceeded")


async def _stop(process) -> None:
    if process.returncode is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
    await process.wait()


async def _reap_spawn(spawn) -> None:
    # Own both startup and reaping independently of the request task. A second
    # deadline may cancel that task while the OS is still creating the child.
    process = await spawn
    await _stop(process)


async def _exchange(process, payload):
    async def write():
        process.stdin.write(payload)
        await process.stdin.drain()
        process.stdin.close()
        await process.stdin.wait_closed()
    _, output = await asyncio.gather(write(), _read_bounded(process.stdout))
    await process.wait()
    if process.returncode != 0:
        # Log only OS status, never wallet payloads, signatures or worker output.
        logger.warning("wallet validation worker exited: returncode=%s", process.returncode)
        raise ValueError("wallet validation worker failed")
    result = _unpack_local(output)
    if not isinstance(result, dict) or set(result) not in ({"value"}, {"error"}):
        raise ValueError("invalid wallet validation worker result")
    if "error" in result:
        raise ValueError(str(result["error"])[:400])
    return result["value"]


async def run_offer_job(job: str, **arguments):
    try:
        return await _run_offer_job(job, arguments)
    except TimeoutError as exc:
        raise ValueError("wallet validation timed out; refresh operation status before retrying") from exc
    except OSError as exc:
        raise ValueError("wallet validation worker is unavailable") from exc


async def _run_offer_job(job: str, arguments):
    if job not in {"decode", "payment", "native", "native_bundle", "voucher", "swap_signature"}:
        raise ValueError("unsupported wallet validation job")
    payload = _pack_local({"job": job, "arguments": arguments})
    loop = asyncio.get_running_loop()
    reference = _LIMITS.get(loop)
    semaphore = reference() if reference is not None else None
    if semaphore is None:
        semaphore = asyncio.Semaphore(MAX_WORKERS)
        _LIMITS[loop] = weakref.ref(semaphore)
    # Queueing, interpreter startup, parsing and evaluation share one deadline.
    async with asyncio.timeout(WORKER_TIMEOUT_SECONDS):
        async with semaphore:
            spawn = asyncio.create_task(asyncio.create_subprocess_exec(
                sys.executable, "-m", "solslot_api.wallet_offer_worker",
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            ))
            try:
                # Cancellation during spawn must not orphan a new process.
                process = await asyncio.shield(spawn)
                return await _exchange(process, payload)
            finally:
                cleanup = asyncio.create_task(_reap_spawn(spawn))
                cancelled = False
                while not cleanup.done():
                    try:
                        await asyncio.shield(cleanup)
                    except asyncio.CancelledError:
                        cancelled = True
                # Keep the concurrency slot until startup and reaping finish,
                # including when more than one caller deadline has expired.
                cleanup.result()
                if cancelled:
                    raise asyncio.CancelledError


def _dispatch(job, arguments):
    if job == "decode":
        from .wallet_offer_validation import decode_offer
        return decode_offer(**arguments)
    if job == "payment":
        from .native_purchases import _parse_prepared_payment_offer
        return _parse_prepared_payment_offer(**arguments)
    if job == "native":
        from .native_purchases import _validate_native_payment_offer
        return _validate_native_payment_offer(**arguments)
    if job == "native_bundle":
        from .native_purchases import _build_native_purchase_spend
        return _build_native_purchase_spend(**arguments)
    if job == "voucher":
        from .presale_endpoints import validate_xch_voucher_offer
        return validate_xch_voucher_offer(**arguments)
    if job == "swap_signature":
        from .sols_swaps import _verify_aggregate_signature
        return _verify_aggregate_signature(**arguments)
    raise ValueError("unsupported wallet validation job")


def main() -> None:
    # Linux is the deployed API platform. The process wall deadline and IPC
    # limits apply on every platform; Linux additionally bounds CPU/address space.
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (15, 15))
        resource.setrlimit(resource.RLIMIT_AS, (2_000_000_000, 2_000_000_000))
    except ImportError:
        pass
    try:
        raw = sys.stdin.buffer.read(MAX_IPC_BYTES + 1)
        request = _unpack_local(raw)
        result = {"value": _dispatch(request["job"], request["arguments"])}
    except Exception as exc:
        result = {"error": str(exc)[:400] or "wallet offer validation failed"}
    sys.stdout.buffer.write(_pack_local(result))
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    # The process entrypoint must use the canonical module for reducers; a
    # __main__ reference would not resolve in the API process.
    from solslot_api.wallet_offer_worker import main as worker_main
    worker_main()
