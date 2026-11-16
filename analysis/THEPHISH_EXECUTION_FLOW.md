# ThePhish Execution Flow (Reverse-Engineered)

Based on `app/thephish_app.py`, `app/list_emails.py`, `app/case_from_email.py`, `app/run_analysis.py`, `app/ws_logger.py`, `app/static/assets/js/thephish.js`.

## 1. End-to-end execution sequence

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser (thephish.js)
    participant F as Flask/Socket.IO (thephish_app.py)
    participant W as WebSocketLogger
    participant L as list_emails.py
    participant I as IMAP
    participant C as case_from_email.py
    participant H as TheHive
    participant R as run_analysis.py
    participant X as Cortex
    participant M as MISP

    B->>F: GET /
    F-->>B: index.html
    B->>F: Socket.IO connect (sid)
    B->>F: GET /list
    F->>L: list_emails.main()
    L->>I: IMAP4_SSL connect/login/select/search UNSEEN/fetch
    L-->>F: emails_info[] or null
    F-->>B: JSON list

    B->>F: POST /analysis (mailUID, sid)
    F->>W: WebSocketLogger(socketio,sid)
    F->>C: case_from_email.main(wsl, mail_uid)
    C->>C: load configs/logging/whitelist, init TheHiveApi
    C->>I: connect, fetch UID, extract internal EML, parse IOCs/attachments
    C->>H: create template/case/observables/tasks
    C-->>F: (case_response, external_from_field)

    F->>R: run_analysis.main(wsl, case, external_from_field)
    R->>R: load configs, init TheHiveApi/Cortex Api, resolve task IDs
    R->>H: update Notification task InProgress + run Mailer responder
    R->>H: update Analysis task InProgress
    R->>H: list observables
    R->>H: run analyzer jobs (special: Yara/UnshortenLink/SPFDMARC scoping)
    R->>X: poll jobs / get reports
    R->>R: normalize levels, count malicious/suspicious, compute verdict
    R->>H: mark malicious observables IOC
    alt verdict == Malicious
        R->>M: export case to MISP (via TheHive)
        R->>H: set Result task description, run Mailer, close task/case (TruePositive/NoImpact)
    else verdict == Safe
        R->>H: set Result task description, run Mailer, close task/case (FalsePositive/NotApplicable)
    else verdict == Suspicious
        R->>H: set Result task description placeholder; leave open
    end
    R-->>F: verdict string
    F-->>B: JSON verdict
    W-->>B: logInfo/logWarning/logError events during processing
```

## 2. Entry points and route behavior

### `GET /` (`thephish_app.py:homepage`)
- **Input:** browser request.
- **Calls:** `flask.render_template("index.html")`.
- **Output:** HTML UI.
- **State:** none.

### `GET /list` (`thephish_app.py:obtain_emails_to_analyze`)
- **Input:** none.
- **Calls:** `list_emails.main()` → IMAP connect + unread EML-attached email extraction.
- **Transform:** list of dicts `{mailUID,date,from,subject,body,attachedMail}`.
- **Output:** JSON array, or `null` on error paths in `list_emails.main()` (module prints/errors and returns implicitly).
- **Exceptions:** handled inside `list_emails.main()` (prints/logs, returns without structured error object).

### `POST /analysis` (`thephish_app.py:analyze_email`)
- **Input:** form fields `mailUID`, `sid` (both `flask.escape`d).
- **Calls:**
  1. `WebSocketLogger(socketio, sid_client)`
  2. `case_from_email.main(wsl, mail_uid)` → `(new_case, external_from_field)`
  3. `run_analysis.main(wsl, new_case, external_from_field)` → verdict
- **Output:** JSON verdict string (`"Safe"|"Malicious"|"Suspicious"`) or `null` on downstream failures.
- **State transitions:** browser UI moves to analyzing/logging/result states driven by response and Socket.IO events.

## 3. `list_emails.py` flow

1. **Config/log setup (`main`)**: load `logging_conf.json`, `configuration.json` (imap host/port/user/password/folder).
2. **Connect (`connect_to_IMAP_server`)**: `IMAP4_SSL(host,port)` + `login(user,password)`.
3. **Retrieve (`retrieve_emails`)**:
   - `select(imapFolder)`
   - `search(None,'(UNSEEN)')`
   - for each UID: `fetch(uid,'(RFC822)')`, parse message, walk MIME parts
   - accept attachment when `Content-Type` in `application/octet-stream` or `message/rfc822` (or filename `.eml`/`content-disposition` attachment heuristics)
   - decode attached EML payload (base64 attempt fallback), capture internal subject
   - extract external fields (UID, Date, From, Subject, text/plain body snippet), append to result
4. **Return:** `emails_info` (possibly empty list). No flag/seen mutation in listing path.

## 4. `case_from_email.py` flow

### `main(wsl, mail_uid)`
1. Load logging, `configuration.json`, `whitelist.json`; build compiled-like regex lists for `domainsInSubdomains/URLs/Emails` plus exact/regex maps.
2. Init `thehive4py.api.TheHiveApi(url, apikey)`.
3. `connect_to_IMAP_server(wsl)` (IMAP SSL login, emits info).
4. `obtain_eml(connection, mail_uid, wsl)`:
   - select folder, search UNSEEN, ensure UID present
   - fetch RFC822 (marks seen by server behavior), parse external `From`
   - locate internal EML part (`message/rfc822` or `application/octet-stream`), decode bytes/string, return `(internal_msg, external_from_field)`
5. `parse_eml(internal_msg, wsl)`:
   - decode internal `Subject` (including split/encoded headers)
   - select header fields for IOC search: To/From/Sender/Cc/Delivered-To/Return-Path/Reply-To/Bounces-to/Received/X-Received/X-OriginatorOrg/X-Sender-IP/X-Originating-IP/X-SenderIP/X-Originating-Email
   - for each selected header value: `search_observables(value)` via `ioc_finder` (`parse_domain_names`, `parse_ipv4_addresses`, `parse_urls`, `parse_email_addresses`) with whitelist checks
   - walk MIME: extract IOCs from `text/plain` and URL-decoded `text/html`; collect non-whitelisted attachments and SHA256 hashes (and whitelist hashes/filenames/filetypes)
   - create in-memory `.eml` observable tuple named `<subject>.eml`
   - sanitize URL observables by splitting on `<`/`>` as workaround
   - return `(subject, observables_header, observables_body, attachments, hashes_attachments, eml_file_tuple)`
6. `create_case(...)`:
   - ensure case template `ThePhish` exists (tasks: `ThePhish notification`, `ThePhish analysis`, `ThePhish result`)
   - create case with title `[ThePhish] <emoji-stripped subject>` (template provides prefix), TLP/PAP/tags/description
   - add observables: header IOCs (tagged by field), body IOCs, file attachments, hash observables, EML sample; `ioc=False` initially
7. Return `(new_case_response, external_from_field)`.

## 5. `run_analysis.py` flow

### `main(wsl, case, mail_to)`
1. Load logging/config (`thehive`, `cortex`, `misp`), analyzer level map, URL whitelist parts.
2. Init `TheHiveApi` and `cortex4py.api.Api`.
3. Resolve task IDs by title (`Notification`, `Analysis`, `Result`).
4. `notify_start_of_analysis`:
   - set Notification task `InProgress`
   - set task description to `mailto:<mail_to>` + start message
   - find responder `Mailer_1_0`; if present run via `api_thehive.run_responder(..., 'case_task', task_id)` and poll Cortex job status until Success/Failure
   - set Notification task `Completed`
5. `analyze_observables`:
   - set Analysis task `InProgress`
   - fetch case observables; build `observables_info` and lists `jobs`, `delayed_jobs`, `reports_observables`
   - discover analyzers per type via `api_cortex.analyzers.get_by_type`
   - per observable:
     - **EML file (`file_message/rfc822`)**: run only `Yara_2_0` (if available)
     - **URL**: run `UnshortenLink_1_2` synchronously (poll to completion); if found and not whitelisted, create new URL observable tagged `unshortened_url` and append for later analysis
     - **Others/URLs (except excluded)**: run applicable analyzers; special scope: `DomainMailSPFDMARC_Analyzer_1_1` only for domain observables in specific header-field tags; skip duplicate UnshortenLink
     - if analyzer start response contains `RateLimitExceeded`, queue in `delayed_jobs`; else record started job
   - retry delayed jobs in loop with `sleep(10)` until queue empty
   - poll all jobs every 5s until each Success/Failure
   - collect reports: extract/override taxonomy levels for specific analyzers (`Pulsedive_GetIndicator_1_0`, `IPVoid_1_0`, `Shodan_Host_1_0`, `Shodan_Host_History_1_0`, `SpamhausDBL_1_0`, `URLhaus_2_0`, default first taxonomy), apply `conf_analyzers_level` mapping by analyzer/datatype
   - set Analysis task `Completed`; return `(observables_info, reports_observables)`
6. `terminate_analysis`:
   - set Result task `InProgress`
   - for each observable count `malicious` and `suspicious` report results
   - if any malicious report: observable considered malicious, increment count, set `ioc=True`
   - if any suspicious report: increment suspicious observables count
   - **Verdict:** `Malicious` if `malicious_observables > 0`; else `Suspicious` if `suspicious_observables > 0`; else `Safe`
   - if final (`Malicious`/`Safe`): export to MISP when malicious, set responder mail body in Result task, run Mailer responder, complete task, resolve/close case (`TruePositive/NoImpact` for malicious, `FalsePositive/NotApplicable` for safe)
   - if `Suspicious`: write placeholder body in Result task and leave task/case open
7. Return verdict.

## 6. State transitions (case/task lifecycle)

- **Case:** created (template `ThePhish`) → observables added → analysis executed → `Resolved` (Safe/Malicious) or remains open (Suspicious).
- **Tasks:**
  - `ThePhish notification`: `Waiting`(template default) → `InProgress` → `Completed` (start notification flow).
  - `ThePhish analysis`: → `InProgress` → `Completed`.
  - `ThePhish result`: → `InProgress` → `Completed` (final verdict) or stays `InProgress`/open context with placeholder description (Suspicious path leaves uncompleted).
- **Observables:** created with `ioc=False`; malicious observables updated to `ioc=True`.
- **External side effects:** Cortex jobs, optional unshortened URL observable creation, optional MISP export, optional Mailer responder emails.

## 7. Notable control/data-flow details

- `/analysis` is a single synchronous HTTP operation that may run for long durations (job polling + sleeps).
- Progress is emitted over Socket.IO to the requesting `sid`; no server-side queue/persistence of progress events.
- `run_analysis.main` signature is `main(wsl, case, mail_to)` and is called accordingly from `thephish_app.py`.
- Whitelist is applied at extraction time in `case_from_email.py` and again for unshortened URLs in `run_analysis.py`; analyzer-level URL whitelist in `run_analysis` only uses URL-related lists.
- Verdict depends on presence of `malicious`/`suspicious` normalized results; observables with only `safe/info/empty` results do not make verdict suspicious by themselves. 
