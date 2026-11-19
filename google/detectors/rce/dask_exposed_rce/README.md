# Exposed Unauthenticated Dask Distributed Cluster RCE Detector

This plugin (`DaskUnauthenticatedRceDetector`) detects exposed unauthenticated
Dask Distributed and NVIDIA RAPIDS (`dask-cuda`) cluster endpoints allowing
arbitrary remote code execution (`DASK_DISTRIBUTED_UNAUTHENTICATED_RCE`).

## Detection Logic

1. **Candidate Services**: Matches raw TCP/TLS Dask Comm ports (`8786` and
   associated service labels) as well as HTTP/HTTPS WebServices for WebSocket
   Dask Comm endpoints (`ws://` / `wss://`) and exposed Dask Bokeh Dashboards
   (`8787` `/json/identity.json`).
2. **Dashboard Comm Discovery**: When scanning an exposed Dask Bokeh Dashboard,
   fetches `GET <prefix>/json/identity.json`, validates the Scheduler schema,
   extracts the advertised `tcp://`, `ws://`, or `wss://` port, and probes that
   port strictly on the authorized target host (never connecting to untrusted
   host strings inside the JSON payload).
3. **Non-Destructive 3-Step Active Verification**:
   - Exchanges the Dask Comm binary MsgPack handshake (`compression: nil`).
   - Queries `{"op": "identity", "reply": true}` to confirm a live Dask
     `Scheduler`, `Worker`, `CUDAWorker`, or `Nanny` daemon (rejecting echo
     servers).
   - Evaluates `operator.add(a, b)` on two random 8-digit integers via
     `run_function` (with worker and nanny `broadcast` -> `run` fallbacks on
     Schedulers, or direct `run` on Workers/CUDAWorkers/Nannies) and verifies
     the exact server-computed sum.

## Build Command

Execute `./gradlew jar` to build the plugin JAR under `build/libs`.
