# GETPASS

GETPASS records visitor entry/exit at public, private, and religious facilities, with student arrival and authorized pickup for schools. PostgreSQL is the Docker deployment target; SQLite is for local development.

## Local development

1. Install Python 3.13 or newer.
2. Copy `.env.example` to `.env`.
3. Generate fresh secrets and put them in `.env`:

   ```powershell
   $keys = & python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()); print(secrets.token_urlsafe(48)); print(secrets.token_urlsafe(48)); print(secrets.token_urlsafe(32))"
   $content = Get-Content .env
   $content = $content -replace '^DATA_ENCRYPTION_KEY=.*$', "DATA_ENCRYPTION_KEY=$($keys[0])"
   $content = $content -replace '^IDENTIFIER_HMAC_KEY=.*$', "IDENTIFIER_HMAC_KEY=$($keys[1])"
   $content = $content -replace '^SESSION_HMAC_KEY=.*$', "SESSION_HMAC_KEY=$($keys[2])"
   $content = $content -replace '^POSTGRES_PASSWORD=.*$', "POSTGRES_PASSWORD=$($keys[3])"
   $encoding = New-Object System.Text.UTF8Encoding -ArgumentList $false
   [System.IO.File]::WriteAllLines((Join-Path (Get-Location) '.env'), $content, $encoding)
   ```

4. Create an isolated environment, install dependencies, and create the first facility administrator:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
   .\.venv\Scripts\python.exe bootstrap.py --slug demo-school --name "Demo School" --admin-email admin@example.test --facility-type public_school
   ```

   The bootstrap command prompts for the administrator password; use at least 12 characters.

5. Start the API and open the port configured by `API_PORT` (8000 by default):

   ```powershell
   .\.venv\Scripts\python.exe main.py
   ```

Facility types are `public_ministry`, `public_hospital`, `public_school`, `private_school`, and `private_hospital`. Choose the ownership and facility type on the sign-in screen; the selection must match the facility account. Gate-operator sign-in protects personal data and records who approves each student release. Existing facilities can change type through the administrator-only `PUT /api/facility/profile` endpoint.

To create fictional local test accounts and a student/guardian roster:

```powershell
.\.venv\Scripts\python.exe seed_demo.py --password "GatePassDemo2026!"
```

Use the password you supplied for either account:

| Facility type | Facility code | Operator email |
|---|---|---|
| Public ministry / state entity | `demo-public` | `gate@demo-public.test` |
| Public school | `demo-school` | `gate@demo-school.test` |

The school demo includes `Demo Learner` (Grade 5) and authorized guardian `Demo Guardian`, ID `DEMO8765`. The visitor form's **Test visitor** button loads fictional check-in details with ID `SAMPLE001`. These accounts and test values are development-only; never use them in production.

## Hosted SaaS pilot

The production Compose file serves multiple facilities from one HTTPS domain while keeping each facility's records scoped to its own tenant ID. It is a single-host pilot setup, not a high-availability production architecture. Use a Linux host with Docker Compose, a domain name, and a static IP; point the domain's DNS A/AAAA records to that host and allow inbound TCP ports 80 and 443.

For Kenyan customer data, first check whether a Kenyan provider/region is required by the customer contract or applicable data-transfer rules. AWS lists Africa (Cape Town), `af-south-1`, as a nearby region, but it is in South Africa rather than Kenya; confirm transfer, service, and customer requirements before selecting it ([AWS region list](https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-regions.html)).

Copy `.env.example` to `.env`, generate unique values for all four secrets, set a strong `POSTGRES_PASSWORD`, then set:

```dotenv
PUBLIC_DOMAIN=gatepass.example.com
TRUSTED_HOSTS=gatepass.example.com,localhost,127.0.0.1
```

Keep `.env` private and out of source control. For production, inject secrets from the hosting provider's secret manager instead of keeping them in a file. Start the HTTPS service:

```powershell
docker compose -p getpass-prod -f docker-compose.production.yml up --build -d
```

Caddy provisions and renews the TLS certificate. Only ports 80 and 443 are public; PostgreSQL and the API are private to the Compose network. Production mode requires secure cookies, a real reader bridge, and explicit trusted host names. Swagger/OpenAPI endpoints are disabled in production.

The service URL is `https://<PUBLIC_DOMAIN>`. The same URL serves every facility; the facility code scopes sign-in and data access. Provision each new facility out-of-band from the host, rather than exposing a public tenant-creation endpoint:

```powershell
docker compose -p getpass-prod -f docker-compose.production.yml run --rm api python bootstrap.py --slug acme-school --name "Example School" --admin-email admin@example.com --facility-type public_school
```

The command prompts for the new facility administrator's password. The facility administrator can then add staff and readers. There is deliberately no unauthenticated self-service facility signup. Store the one-time reader token returned by `POST /api/readers` in the reader bridge's secret storage; revoke it with `DELETE /api/readers/{reader_id}` if the reader is lost.

For a real commercial launch, prefer a managed PostgreSQL service with automated encrypted backups and point-in-time recovery, a managed secret store, monitoring/alerts, and a documented restore test. A single VM and Docker volume can fail or be lost; it is suitable only for a controlled pilot until backups and recovery are independently verified.

## Backend behavior

- Staff accounts belong to a facility and have `facility_admin`, `operator`, or `viewer` roles. Data queries are always scoped to the signed-in staff member’s facility.
- Staff sessions use opaque, HttpOnly, SameSite cookies, CSRF headers, scrypt password hashes, session expiry, and account lockout after repeated failed logins.
- Visitor passes include general visitor, parent/guardian, event guest, contractor, and delivery categories. Visitor names, ID/passport numbers, phone numbers, host, and purpose are encrypted before database storage; keyed HMACs support document lookup. The full ID number is shown in visit records only to facility administrators and gate operators; viewers see a masked number.
- School facilities can maintain a student roster and each student's authorized guardian roster. Student names, class, admission/registration numbers, guardian names, relationship, and movement notes are encrypted; guardian ID/passport numbers are represented by a keyed HMAC and last four characters. Admission/registration numbers are unique within each facility. `GET /api/students` reports each student's current status from their latest movement: an arrival/return means `in_session`, while a departure or no recorded movement means `checked_out`. Every student departure requires an active roster match, a reader verification for that guardian, and explicit gate-operator approval. Arrivals/returns are recorded with their context and operator.
- Facility administrators manage the roster and revoke guardian authorizations. Gate operators can record arrivals and approve departures; viewers can review records but cannot perform gate actions.
- Reader devices receive a one-time credential from the facility-admin-only `POST /api/readers` endpoint. For a first check-in, the combined ID/fingerprint reader submits the ID's full name and document fields, a match result, a nonce, and an opaque `reader_subject_ref`; the app autofills the form, encrypts the scanned ID data, and enrolls a keyed reference to the visitor profile. A returning visitor can send `action: "repeat_checkin"` with only the matched `reader_subject_ref` and a fresh nonce; the server creates a timestamped visit without asking for the ID again. The local reader keeps fingerprint templates and stable subject references. At visitor check-out, a standalone fingerprint reader sends the same reference and match result; no ID scan is needed. The browser selects the active visit and waits for its short-lived result. The bridge must use HTTPS and protect its credential.
- The development-only `/api/demo/reader-verifications` endpoint is disabled in production. The demo has a returning-fingerprint test button after the sample visitor has been checked in once. No fingerprint images or templates are accepted or stored; the reader bridge must perform local matching and attest the result.
- Audit events record staff, reader, visitor, roster, and student movement actions. The dashboard refreshes from the central API every five seconds.

## API endpoints

Use the API base URL `https://<PUBLIC_DOMAIN>` after deployment. JSON APIs are same-origin; do not enable permissive CORS for facility browsers.

| Endpoint | Purpose |
|---|---|
| `GET /api/health/live`, `GET /api/health/ready` | Service and database health checks |
| `GET /api/config` | Non-sensitive reader mode and environment information |
| `POST /api/auth/login`, `GET /api/auth/session`, `POST /api/auth/logout` | Facility-scoped staff sessions |
| `PUT /api/facility/profile` | Change facility type |
| `GET /api/staff`, `POST /api/staff` | Facility-admin staff management |
| `GET /api/visits?view=active`, `GET /api/visits?view=all` | Current and historical visitor passes |
| `POST /api/checkin`, `POST /api/checkout` | Gate operator visitor entry and exit |
| `GET /api/audit` | Facility audit history |
| `GET /api/students`, `POST /api/students` | School roster |
| `POST /api/students/{student_id}/guardians`, `DELETE /api/guardians/{guardian_id}` | Authorized guardian roster |
| `POST /api/students/{student_id}/arrivals`, `POST /api/students/{student_id}/departures`, `GET /api/students/movements` | Student gate movements |
| `POST /api/readers`, `GET /api/readers`, `DELETE /api/readers/{reader_id}` | Facility reader registration and revocation |
| `POST /api/reader/verifications` | Reader bridge check-in, repeat check-in, and checkout; requires `X-Reader-Token` |
| `GET /api/reader/verifications/pending` | Authenticated gate UI polls for a reader result |

Staff APIs require the facility session cookie; state-changing browser requests also require `X-CSRF-Token`. Facility creation is currently an operator-run `bootstrap.py` command, not a public API. The interactive API explorer is available only in development at <http://127.0.0.1:8000/api/docs>. Run the tests with:

```powershell
.\.venv\Scripts\python.exe -m unittest -v
```

## Before a live rollout

This is not yet a certified hardware integration. The scanner manufacturer/model, operating system, and SDK/bridge are unknown, so compatibility with a specific device cannot be confirmed. The generic bridge contract above is implemented and tested; vendor-specific ID parsing, fingerprint enrollment/matching, and device communications still need that hardware information. School rosters are entered by an administrator; no SIS integration or guardian-notification service is included.

Before selling or processing real visitor/student data, determine each facility's data-controller responsibilities and GETPASS's processor responsibilities, complete a Kenyan privacy/data-protection review (including whether a DPIA or ODPC registration is required), set retention/deletion and breach-response procedures, and agree data export/deletion terms with customers. Do not sell or reuse visitor/student records. The production Compose setup still requires managed secret storage, managed database backups and restore tests, database migrations, monitoring, and edge rate limits before broad rollout. The previous demo SQLite file is not migrated automatically and must not be used as a production source.

## Reader hardware concept

The concept preview is available at `/hardware-design` and the PDF at `/hardware-design.pdf`. It describes a compact entry document/fingerprint station and a separate fingerprint checkout reader, with indicative Kenya-shilling costs and the existing reader API flow. The drawings are concept layouts, not production CAD or a tested bill of materials. Prices are planning estimates, and the selected camera, fingerprint reader, operating system, and SDK must be bench-tested with the reader bridge before procurement. The 150 mm enclosure uses a fold-out passport support; no design can guarantee zero latency or zero downtime, so offline buffering and idempotent replay require additional implementation and validation.
