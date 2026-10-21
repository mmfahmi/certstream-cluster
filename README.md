# certstream-gcp

Self-hosted CertStream collector, designed to run cheaply on a GCP e2-micro
free-tier instance.

```
CT Logs (inbound, free)
        |
        v
certstream-server-go   (Docker, memory-capped, lite endpoint)
        |  ws://certstream:8080/lite
        v
Python collector       (Docker, memory-capped)
        |
        v
GCS bucket, same region (free egress)
```

## Why this design

- **certstream-server-go**, not the original Elixir `CaliDog/certstream-server`
  — actively maintained, small footprint, drop-in compatible. Watches the
  full Google CT log list by default.
- **`/lite` endpoint** — server-side, drops the raw DER and full chain
  before it ever hits the wire, so the collector only receives leaf cert
  fields (issuer, validity dates, SAN domains). Less data in flight, less
  parsing work, less memory pressure.
- **No public port exposed** — the certstream container has no published
  host port; only the collector (on the same Docker network) can reach it.
- **Local-buffer-then-upload** — the collector writes each batch to local
  disk first, then uploads to GCS. If the upload fails, the file just sits
  on disk and a background retry loop picks it up later. Nothing is lost to
  a transient network blip.
- **Same-region GCS bucket** — writes from the VM to a bucket in the same
  region don't count against GCP's 1GB/month free internet egress; only
  reads to the internet do, and this collector never serves data outward.

## Run locally

The collector can run without Google Cloud credentials. In this mode it
writes compressed JSONL batches to `./data/buffer` and leaves them there.

To start the CertStream container, collector, and cluster viewer together,
run the launcher from the repo:

```bash
./run-local.sh
```

Open <http://127.0.0.1:8765/>. The launcher flushes collector batches every
30 seconds by default and stops all three processes when you press Ctrl-C.
Override the batch interval with `FLUSH_INTERVAL_SECONDS=... ./run-local.sh`.

```bash
# Start only the CertStream server. Its local preview is available at
# ws://localhost:8081/ (the local config serves the lite stream at `/`).
docker compose up -d certstream

# Set up and run the collector on your machine.
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
CERTSTREAM_URL=ws://localhost:8081/ \
LOCAL_BUFFER_DIR=./data/buffer \
python collector.py
```

Stop the collector with Ctrl-C. Batches are stored under
`./data/buffer/YYYY/MM/DD/` as `.jsonl.zst` files. To stop the CertStream
server, run `docker compose stop certstream`. Set `GCS_BUCKET` and configure
Google Cloud Application Default Credentials to enable uploads while running
locally.

### Find bursts of similar registered domains

The temporal clustering utility reads the collector's `.jsonl.zst` files,
reduces hostnames to registered domains using the bundled public suffix list,
and reports groups first observed within one hour that share naming patterns
or certificate evidence. Install project dependencies, then run:

```bash
python utils/temporal_clustering.py ./data/buffer \
  --window-hours 1 \
  --min-size 3 \
  --output ./data/domain-clusters.json
```

Adjust `--window-hours`, `--similarity` (0 to 1), and `--min-size` to tune
the results. This is a similarity-based triage signal; review cluster evidence
before treating a group as malicious.

To watch results in a browser while the collector continues writing batches,
run the same analysis in viewer mode:

```bash
python utils/temporal_clustering.py ./data/buffer \
  --serve \
  --window-hours 1 \
  --min-size 3 \
  --output ./data/domain-clusters.json
```

Open <http://127.0.0.1:8765/>. The page refreshes every minute and includes
domain filtering and per-link similarity evidence. The JSON output file is
also refreshed on each page poll. Stop the viewer with Ctrl-C.

## 1. GCP setup

### Create the VM (free tier)

Pick one of the three free-tier regions: `us-west1`, `us-central1`, or
`us-east1`.

```bash
gcloud compute instances create certstream-collector \
  --zone=us-central1-a \
  --machine-type=e2-micro \
  --image-family=debian-12 \
  --image-project=debian-cloud \
  --boot-disk-size=30GB \
  --boot-disk-type=pd-standard \
  --no-address
```

`--no-address` skips the public IP — use `gcloud compute ssh` (via IAP) to
connect, which avoids exposing the box to the internet at all.

### Create the bucket (same region as the VM)

```bash
gsutil mb -l us-central1 -b on gs://your-bucket-name
gsutil lifecycle set gcs/lifecycle.json gs://your-bucket-name
```

### Create a service account scoped to just this bucket

```bash
gcloud iam service-accounts create certstream-collector \
  --display-name="certstream collector"

gsutil iam ch \
  serviceAccount:certstream-collector@YOUR_PROJECT.iam.gserviceaccount.com:roles/storage.objectCreator \
  gs://your-bucket-name

gcloud iam service-accounts keys create secrets/gcs-key.json \
  --iam-account=certstream-collector@YOUR_PROJECT.iam.gserviceaccount.com
```

Keep `secrets/gcs-key.json` out of version control (see `.gitignore`).

## 2. Deploy to the VM

```bash
gcloud compute ssh certstream-collector --zone=us-central1-a

# on the VM:
sudo apt update && sudo apt install -y docker.io docker-compose-plugin
sudo usermod -aG docker $USER   # log out/in after this

sudo mkdir -p /opt/certstream-gcp
sudo chown $USER /opt/certstream-gcp
# copy this repo's contents (scp, git clone, etc.) into /opt/certstream-gcp,
# including secrets/gcs-key.json

cd /opt/certstream-gcp
cp .env.example .env
# edit .env: set GCS_BUCKET and GCP_REGION

docker compose up -d
```

### Run on boot / auto-restart

```bash
sudo cp systemd/certstream-stack.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now certstream-stack
```

## 3. Verify it's working

```bash
docker compose logs -f collector
```

You should see periodic `wrote N records -> ...` / `uploaded ...` lines.
Check the bucket:

```bash
gsutil ls -r gs://your-bucket-name/**
```

Objects land under `YYYY/MM/DD/HHMMSS-N.jsonl.zst`.

## 4. Resource guardrails already in place

| Guardrail | Where |
|---|---|
| `mem_limit: 200m` on certstream | `docker-compose.yml` |
| `mem_limit: 150m` on collector | `docker-compose.yml` |
| Docker log rotation (10MB x 3 files) | `docker-compose.yml`, both services |
| GCS lifecycle: Nearline at 30d, delete at 90d | `gcs/lifecycle.json` |
| `Restart=always` at container and systemd level | `docker-compose.yml`, `systemd/certstream-stack.service` |
| No public port on certstream | `docker-compose.yml` (uses `expose`, not `ports`) |

Adjust the lifecycle rule if you want to keep raw data longer — the
connected-component graph analysis benefits from historical continuity, so
don't set the delete age too aggressively if you plan to do that later.

## 5. Record schema

```json
{"ts": 1755680000, "id": 123456789, "issuer": "Let's Encrypt", "not_before": 1755600000, "not_after": 1763376000, "domains": ["a.example.com", "b.example.com"]}
```

This is enough to rebuild a certificate-to-domain bipartite graph later
(via DuckDB/Parquet + NetworkX/igraph) without needing a graph database
from day one.
