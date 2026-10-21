"""Find temporally close registered domains with similar naming patterns.

Input is the collector's compressed JSONL output. The script aggregates each
registered domain, then links pairs that first appeared within the time window
and share lexical or certificate characteristics. Connected components with
at least ``--min-size`` domains are emitted as JSON.
"""

from __future__ import annotations

import argparse
import itertools
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import tldextract
import zstandard

# Use tldextract's bundled suffix snapshot: analysis stays deterministic and
# does not need to fetch the public suffix list at runtime.
_extract_domain = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
_TOKEN_RE = re.compile(r"[a-z]+|\d+", re.IGNORECASE)


def input_files(path: Path):
    if path.is_file():
        yield path
    elif path.is_dir():
        yield from sorted(path.rglob("*.jsonl.zst"))
    else:
        raise FileNotFoundError(path)


def read_records(paths):
    for path in paths:
        try:
            with zstandard.open(path, "rt", encoding="utf-8") as reader:
                for line_number, line in enumerate(reader, 1):
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError as exc:
                        print(f"skip malformed JSON {path}:{line_number}: {exc}", file=sys.stderr)
                        continue
                    yield record
        except zstandard.ZstdError as exc:
            print(f"skip unreadable zstd file {path}: {exc}", file=sys.stderr)


def registered_domain(host: str) -> str | None:
    host = host.strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    if not host or ":" in host:
        return None
    extracted = _extract_domain(host)
    if not extracted.domain or not extracted.suffix:
        return None
    return f"{extracted.domain}.{extracted.suffix}"


def domain_features(domain: str):
    extracted = _extract_domain(domain)
    name = extracted.domain.lower()
    padded = f"^{name}$"
    trigrams = {padded[i:i + 3] for i in range(max(0, len(padded) - 2))}
    return {
        "name": name,
        "trigrams": trigrams,
        "tokens": set(_TOKEN_RE.findall(name)),
        "length": len(name),
        "has_digits": any(c.isdigit() for c in name),
        "has_hyphen": "-" in name,
    }


def aggregate(records):
    domains = {}
    for record in records:
        try:
            timestamp = int(record["ts"])
        except (KeyError, TypeError, ValueError):
            continue
        issuer = record.get("issuer")
        cert_id = record.get("id")
        for host in record.get("domains") or []:
            if not isinstance(host, str):
                continue
            domain = registered_domain(host)
            if domain is None:
                continue
            item = domains.setdefault(domain, {
                "first_seen": timestamp,
                "last_seen": timestamp,
                "observations": 0,
                "issuers": set(),
                "cert_ids": set(),
            })
            item["first_seen"] = min(item["first_seen"], timestamp)
            item["last_seen"] = max(item["last_seen"], timestamp)
            item["observations"] += 1
            if issuer:
                item["issuers"].add(str(issuer).strip().lower())
            if cert_id is not None:
                item["cert_ids"].add(str(cert_id))
    for domain, item in domains.items():
        item["features"] = domain_features(domain)
    return domains


def similarity(left, right):
    a, b = left["features"], right["features"]
    grams_union = a["trigrams"] | b["trigrams"]
    lexical = len(a["trigrams"] & b["trigrams"]) / len(grams_union) if grams_union else 0.0
    token_union = a["tokens"] | b["tokens"]
    tokens = len(a["tokens"] & b["tokens"]) / len(token_union) if token_union else 0.0
    structural = sum((a[key] == b[key]) for key in ("has_digits", "has_hyphen")) / 2
    structural += max(0.0, 1 - abs(a["length"] - b["length"]) / max(a["length"], b["length"], 1))
    structural /= 2
    issuers = left["issuers"] & right["issuers"]
    shared_certs = left["cert_ids"] & right["cert_ids"]
    # Lexical similarity is the main signal. Issuer overlap is deliberately
    # weak because large certificate authorities issue unrelated certs.
    score = 0.60 * lexical + 0.15 * tokens + 0.20 * structural + 0.05 * bool(issuers)
    if shared_certs:
        score = max(score, 0.85)
    return score, issuers, shared_certs


def cluster(domains, window_seconds=3600, threshold=0.48, min_size=3):
    """Return connected components of temporally and structurally similar domains."""
    names = sorted(domains)
    if not names:
        return []

    # Inverted trigram index avoids comparing every domain pair. Very common
    # grams are skipped to keep large input batches tractable; same-certificate
    # evidence is indexed separately and remains available.
    gram_index = defaultdict(list)
    cert_index = defaultdict(list)
    for name in names:
        for gram in domains[name]["features"]["trigrams"]:
            gram_index[gram].append(name)
        for cert_id in domains[name]["cert_ids"]:
            cert_index[cert_id].append(name)

    candidates = set()
    for members in gram_index.values():
        if len(members) <= 200:
            candidates.update(itertools.combinations(members, 2))
    for members in cert_index.values():
        candidates.update(itertools.combinations(members, 2))

    parent = {name: name for name in names}
    root_min = {name: domains[name]["first_seen"] for name in names}
    root_max = dict(root_min)

    def find(name):
        while parent[name] != name:
            parent[name] = parent[parent[name]]
            name = parent[name]
        return name

    edges = []
    for a, b in candidates:
        left, right = domains[a], domains[b]
        if abs(left["first_seen"] - right["first_seen"]) > window_seconds:
            continue
        score, issuers, certs = similarity(left, right)
        if score < threshold:
            continue
        root_a, root_b = find(a), find(b)
        if root_a != root_b:
            merged_min = min(root_min[root_a], root_min[root_b])
            merged_max = max(root_max[root_a], root_max[root_b])
            # Prevent a chain of individually close sightings from stretching
            # one reported "burst" across an arbitrarily long period.
            if merged_max - merged_min > window_seconds:
                continue
            parent[root_b] = root_a
            root_min[root_a], root_max[root_a] = merged_min, merged_max
        edges.append({
            "domains": [a, b],
            "similarity": round(score, 3),
            "shared_issuers": sorted(issuers),
            "shared_cert_ids": sorted(certs),
        })

    linked_names = {name for edge in edges for name in edge["domains"]}
    components = defaultdict(list)
    for name in names:
        if name in linked_names:
            components[find(name)].append(name)

    results = []
    for members in components.values():
        if len(members) < min_size:
            continue
        member_set = set(members)
        component_edges = [edge for edge in edges if set(edge["domains"]) <= member_set]
        first_seen = min(domains[name]["first_seen"] for name in members)
        last_seen = max(domains[name]["first_seen"] for name in members)
        results.append({
            "first_seen": datetime.fromtimestamp(first_seen, timezone.utc).isoformat(),
            "last_first_seen": datetime.fromtimestamp(last_seen, timezone.utc).isoformat(),
            "domain_count": len(members),
            "domains": [
                {
                    "domain": name,
                    "first_seen": datetime.fromtimestamp(domains[name]["first_seen"], timezone.utc).isoformat(),
                    "observations": domains[name]["observations"],
                    "issuers": sorted(domains[name]["issuers"]),
                }
                for name in sorted(members, key=lambda n: domains[n]["first_seen"])
            ],
            "evidence": component_edges,
        })
    return sorted(results, key=lambda item: item["first_seen"])


def build_report(input_path, window_hours, threshold, min_size):
    domains = aggregate(read_records(input_files(input_path)))
    return {
        "parameters": {
            "window_hours": window_hours,
            "similarity_threshold": threshold,
            "minimum_cluster_size": min_size,
            "registered_domains_analyzed": len(domains),
        },
        "clusters": cluster(domains, int(window_hours * 3600), threshold, min_size),
    }


VIEWER_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="">
<title>Temporal domain clusters</title>
<style>
:root{color-scheme:dark;--bg:#10151d;--panel:#19222e;--line:#2b3949;--text:#e7edf4;--muted:#a6b4c4;--accent:#77d4b0}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,sans-serif}
header{position:sticky;top:0;background:#10151ded;border-bottom:1px solid var(--line);padding:18px max(20px,calc((100% - 1100px)/2));z-index:2}
h1{font-size:21px;margin:0 0 8px}.meta{color:var(--muted);font-size:13px}.toolbar{display:flex;gap:12px;align-items:center;margin-top:12px;flex-wrap:wrap}
input{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:7px;padding:9px 11px;min-width:260px}
main{max-width:1100px;margin:22px auto;padding:0 20px}.cluster{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin:14px 0;padding:16px}
.cluster h2{font-size:17px;margin:0 0 4px}.muted{color:var(--muted)}.domains{display:flex;flex-wrap:wrap;gap:7px;margin:13px 0}
.domain{font:13px ui-monospace,monospace;background:#202d39;border:1px solid #324354;border-radius:5px;padding:4px 7px}
details{border-top:1px solid var(--line);padding-top:9px}summary{cursor:pointer;color:var(--accent)}.evidence{font-size:13px;color:var(--muted);margin:8px 0}
#status{color:var(--muted)}.empty{padding:36px;text-align:center;color:var(--muted);border:1px dashed var(--line);border-radius:10px}
</style></head><body>
<header><h1>Temporal domain clusters</h1><div id="summary" class="meta">Loading cluster data…</div>
<div class="toolbar"><input id="filter" type="search" placeholder="Filter by registered domain"><span id="status"></span></div></header>
<main id="clusters"></main>
<script>
const refreshSeconds=60; let report=null;
const esc=v=>String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
function render(){if(!report)return;const q=document.querySelector('#filter').value.trim().toLowerCase();
 const found=report.clusters.filter(c=>!q||c.domains.some(d=>d.domain.toLowerCase().includes(q)));
 document.querySelector('#summary').textContent=`${report.parameters.registered_domains_analyzed.toLocaleString()} registered domains · ${report.clusters.length} clusters · refreshed ${new Date().toLocaleTimeString()}`;
 const root=document.querySelector('#clusters');
 if(!found.length){root.innerHTML='<div class="empty">No matching clusters found.</div>';return}
 root.innerHTML=found.map((c,i)=>`<section class="cluster"><h2>Cluster ${i+1} · ${c.domain_count} domains</h2>
 <div class="muted">First seen ${esc(c.first_seen)}${c.last_first_seen!==c.first_seen?' · last first-seen '+esc(c.last_first_seen):''}</div>
 <div class="domains">${c.domains.map(d=>`<span class="domain" title="${d.observations} observations">${esc(d.domain)}</span>`).join('')}</div>
 <details><summary>${c.evidence.length} similarity links</summary>${c.evidence.map(e=>`<div class="evidence"><b>${esc(e.domains.join(' ↔ '))}</b> · score ${esc(e.similarity)}${e.shared_cert_ids.length?' · shared certificate '+esc(e.shared_cert_ids.join(', ')):''}${e.shared_issuers.length?' · issuer '+esc(e.shared_issuers.join(', ')):''}</div>`).join('')}</details></section>`).join('');
}
async function update(){const s=document.querySelector('#status');try{const r=await fetch('/api/clusters',{cache:'no-store'});if(!r.ok)throw Error(`HTTP ${r.status}`);report=await r.json();render();s.textContent=`Auto-refresh every ${refreshSeconds}s`;}catch(e){s.textContent=`Could not load data: ${e.message}`;}}
document.querySelector('#filter').addEventListener('input',render); update(); setInterval(update,refreshSeconds*1000);
</script></body></html>"""


def serve(args):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/" or self.path.startswith("/?"):
                body = VIEWER_HTML.encode("utf-8")
                content_type = "text/html; charset=utf-8"
            elif self.path == "/api/clusters":
                report = build_report(args.input, args.window_hours, args.similarity, args.min_size)
                body = (json.dumps(report, separators=(",", ":")) + "\n").encode("utf-8")
                if args.output:
                    args.output.parent.mkdir(parents=True, exist_ok=True)
                    args.output.write_bytes(body)
                content_type = "application/json; charset=utf-8"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            print(f"[{self.log_date_time_string()}] {format % args}", file=sys.stderr)

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Viewing clusters at http://{args.host}:{server.server_port}/ (refreshes every 60 seconds)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping cluster viewer.")
    finally:
        server.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, nargs="?", default=Path("./data/buffer"),
                        help="a .jsonl.zst file or directory containing them (default: ./data/buffer)")
    parser.add_argument("--window-hours", type=float, default=1.0,
                        help="maximum difference between first sightings (default: 1 hour)")
    parser.add_argument("--similarity", type=float, default=0.48,
                        help="minimum pair similarity from 0 to 1 (default: 0.48)")
    parser.add_argument("--min-size", type=int, default=3,
                        help="minimum number of domains in a reported cluster (default: 3)")
    parser.add_argument("--output", type=Path, help="write JSON here instead of stdout")
    parser.add_argument("--serve", action="store_true", help="serve an auto-refreshing local web viewer")
    parser.add_argument("--host", default="127.0.0.1", help="viewer bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="viewer port (default: 8765)")
    args = parser.parse_args()
    if args.window_hours <= 0 or not 0 <= args.similarity <= 1 or args.min_size < 2:
        parser.error("window-hours must be positive, similarity 0..1, and min-size at least 2")

    if not 0 < args.port < 65536:
        parser.error("port must be between 1 and 65535")
    if args.serve:
        serve(args)
        return

    result = build_report(args.input, args.window_hours, args.similarity, args.min_size)
    output = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)


if __name__ == "__main__":
    main()
