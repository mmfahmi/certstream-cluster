"""
CertStream -> GCS collector.

Connects to a self-hosted certstream-server-go instance (lite endpoint),
extracts leaf certificate SAN domains, batches them into compressed
JSONL files, and uploads them to GCS. If a GCS upload fails, the batch
stays on local disk and is retried automatically so no data is lost
across a transient network blip.
"""

import json
import os
import queue
import signal
import sys
import threading
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

import websocket
import zstandard as zstd
from google.cloud import storage

# --- Config (env vars, with sane defaults) ---------------------------------

CERTSTREAM_URL = os.environ.get("CERTSTREAM_URL", "ws://certstream:8080/lite")
GCS_BUCKET = os.environ.get("GCS_BUCKET", "").strip()
FLUSH_INTERVAL_SECONDS = int(os.environ.get("FLUSH_INTERVAL_SECONDS", "300"))
FLUSH_MAX_RECORDS = int(os.environ.get("FLUSH_MAX_RECORDS", "50000"))
LOCAL_BUFFER_DIR = Path(os.environ.get("LOCAL_BUFFER_DIR", "/data/buffer"))
PING_INTERVAL = 30
PING_TIMEOUT = 10
RETRY_SCAN_SECONDS = 60

LOCAL_BUFFER_DIR.mkdir(parents=True, exist_ok=True)

record_queue: "queue.Queue[dict]" = queue.Queue()
shutdown_event = threading.Event()

bucket = None
if GCS_BUCKET:
    storage_client = storage.Client()
    bucket = storage_client.bucket(GCS_BUCKET)

_zstd_compressor = zstd.ZstdCompressor(level=19)


def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    print(f"[{ts}] {msg}", flush=True)


# --- WebSocket handling ------------------------------------------------------

def on_message(ws, message):
    try:
        msg = json.loads(message)
    except json.JSONDecodeError:
        return

    if msg.get("message_type") != "certificate_update":
        return

    data = msg.get("data", {})
    leaf = data.get("leaf_cert", {})
    domains = leaf.get("all_domains") or []
    if not domains:
        return

    record = {
        "ts": int(time.time()),
        "id": data.get("cert_index"),
        "issuer": (leaf.get("issuer") or {}).get("O"),
        "not_before": leaf.get("not_before"),
        "not_after": leaf.get("not_after"),
        "domains": domains,
    }
    record_queue.put(record)


def on_error(ws, error):
    log(f"websocket error: {error}")


def on_close(ws, close_status_code, close_msg):
    log(f"websocket closed: {close_status_code} {close_msg}")


def on_open(ws):
    log(f"connected to {CERTSTREAM_URL}")


def ws_loop():
    """Run the websocket client with auto-reconnect and exponential backoff."""
    backoff = 1
    while not shutdown_event.is_set():
        ws = websocket.WebSocketApp(
            CERTSTREAM_URL,
            on_message=on_message,
            on_error=on_error,
            on_close=on_close,
            on_open=on_open,
        )
        try:
            # ping_interval/ping_timeout keep the connection alive - the
            # server disconnects clients that don't ping within 60s.
            ws.run_forever(ping_interval=PING_INTERVAL, ping_timeout=PING_TIMEOUT)
        except Exception:
            log(f"ws_loop exception:\n{traceback.format_exc()}")

        if shutdown_event.is_set():
            break

        log(f"reconnecting in {backoff}s...")
        time.sleep(backoff)
        backoff = min(backoff * 2, 60)
    log("ws_loop exiting")


# --- Batching + upload --------------------------------------------------------

def _write_local(records: list) -> Path:
    now = datetime.now(timezone.utc)
    fname = f"{now:%Y%m%d-%H%M%S}-{len(records)}.jsonl.zst"
    day_dir = LOCAL_BUFFER_DIR / f"{now:%Y}/{now:%m}/{now:%d}"
    day_dir.mkdir(parents=True, exist_ok=True)
    path = day_dir / fname

    lines = "\n".join(json.dumps(r, separators=(",", ":")) for r in records).encode()
    compressed = _zstd_compressor.compress(lines)
    path.write_bytes(compressed)
    return path


def _upload_file(local_path: Path) -> bool:
    """Upload a single local buffer file to GCS. Returns True on success."""
    if bucket is None:
        return False
    rel = local_path.relative_to(LOCAL_BUFFER_DIR)
    blob_path = str(rel).replace(os.sep, "/")
    try:
        blob = bucket.blob(blob_path)
        blob.upload_from_filename(str(local_path), content_type="application/zstd")
        local_path.unlink()
        return True
    except Exception:
        log(f"upload failed for {local_path}:\n{traceback.format_exc()}")
        return False


def flush(records: list) -> None:
    if not records:
        return
    local_path = _write_local(records)
    log(f"wrote {len(records)} records -> {local_path}")
    if bucket is None:
        log("GCS_BUCKET is unset; keeping batch in the local buffer")
        return
    if _upload_file(local_path):
        log(f"uploaded {local_path.name} -> gs://{GCS_BUCKET}/{local_path.relative_to(LOCAL_BUFFER_DIR)}")
    else:
        log(f"left {local_path} on disk for retry")


def flush_loop():
    buf = []
    last_flush = time.time()
    while not shutdown_event.is_set():
        try:
            item = record_queue.get(timeout=5)
            buf.append(item)
        except queue.Empty:
            pass

        now = time.time()
        should_flush = buf and (
            len(buf) >= FLUSH_MAX_RECORDS or (now - last_flush) >= FLUSH_INTERVAL_SECONDS
        )
        if should_flush:
            flush(buf)
            buf = []
            last_flush = now

    # final flush on shutdown
    if buf:
        flush(buf)
    log("flush_loop exiting")


def retry_loop():
    """Periodically retry uploading any local files left over from failed
    uploads or a previous crash."""
    while bucket is not None and not shutdown_event.wait(RETRY_SCAN_SECONDS):
        leftovers = list(LOCAL_BUFFER_DIR.rglob("*.jsonl.zst"))
        if not leftovers:
            continue
        log(f"retrying {len(leftovers)} buffered file(s)")
        for path in leftovers:
            _upload_file(path)
    log("retry_loop exiting")


# --- Entry point --------------------------------------------------------------

def handle_signal(signum, frame):
    log(f"received signal {signum}, shutting down...")
    shutdown_event.set()


def main():
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    destination = f"gs://{GCS_BUCKET}" if GCS_BUCKET else f"local:{LOCAL_BUFFER_DIR}"
    log(f"starting collector, destination={destination}, url={CERTSTREAM_URL}")

    threads = [
        threading.Thread(target=ws_loop, name="ws_loop", daemon=True),
        threading.Thread(target=flush_loop, name="flush_loop", daemon=True),
        threading.Thread(target=retry_loop, name="retry_loop", daemon=True),
    ]
    for t in threads:
        t.start()

    while not shutdown_event.is_set():
        time.sleep(1)

    for t in threads:
        t.join(timeout=30)
    log("shutdown complete")


if __name__ == "__main__":
    main()
