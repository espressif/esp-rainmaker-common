# rmaker_aws_sign

[![Component Registry](https://components.espressif.com/components/espressif/rmaker_aws_sign/badge.svg)](https://components.espressif.com/components/espressif/rmaker_aws_sign)

AWS Signature Version 4 request signing with the device X.509 certificate as its identity: one path
for every feature that calls an AWS service directly.

```
device cert ──► AWS IoT Credential Provider (role alias) ──► temporary SigV4 credentials
                                                                   │
                          SigV4-sign the request (service/region) ─┘
                                                                   │
                                              send over TLS ───────► AWS service
```

## Overview

Three tiers, each usable on its own:

| Layer | Entry point | Job |
|---|---|---|
| SigV4 signer | `esp_rmaker_aws_sign_sigv4()` | canonical request → string-to-sign → HMAC chain → header |
| Credentials | `esp_rmaker_aws_sign_creds_refresh()` | mTLS to the IoT Credential Provider, parse into a caller-owned struct |
| Signed request | `esp_rmaker_aws_sign_send_request()` | credentials + signature + HTTPS in one call |

Only `service` and `role_alias` change between features — `s3` for file storage, `kinesisvideo` for
camera streaming, `execute-api` for a REST API.

```c
esp_rmaker_aws_sign_config_t cfg = {
    .cred_host = "c1abcdef.credentials.iot.us-east-1.amazonaws.com",
    .thing_name = "node1234",
    .client_cert = device_cert_pem,      /* len 0 => PEM, non-zero => DER */
    .client_key = device_key_pem,
};
esp_rmaker_aws_sign_port_install_default();      /* once for the whole process */
esp_rmaker_aws_sign_handle_t h;
esp_rmaker_aws_sign_create(&cfg, &h);            /* one per identity, owned by the caller */

static esp_rmaker_aws_sign_creds_t node_creds;   /* one per role alias, kept across calls */

esp_rmaker_aws_sign_request_t req = {
    .method = "GET", .host = "abc.execute-api.us-east-1.amazonaws.com",
    .path = "/prod/v1/node", .service = "execute-api", .role_alias = "node_role_alias",
    .creds = &node_creds,
};
esp_rmaker_aws_sign_response_t resp = {0};
if (esp_rmaker_aws_sign_send_request(h, &req, &resp) == ESP_OK) {
    /* resp.status_code, resp.body, resp.body_len */
    esp_rmaker_aws_sign_response_free(&resp);
}
```

The caller owns the credentials. `esp_rmaker_aws_sign_send_request()` and
`esp_rmaker_aws_sign_creds_refresh()` fetch new ones only when the struct is empty, within
`CONFIG_ESP_RMAKER_AWS_SIGN_CREDS_REFRESH_MARGIN_SEC` of expiry, or older than the last
`esp_rmaker_aws_sign_set_cred_host()`. If new credentials arrive with less than twice the margin
left, the refresh happens halfway to their expiry instead. For example, with the default 300 s
margin, credentials that arrive with 120 s left are used for 60 s. Each struct costs about 1.5 KB of heap while it holds
credentials. Only the component fills a struct, and a filled struct refuses another role alias
with `ESP_ERR_INVALID_ARG`. Release it with `esp_rmaker_aws_sign_creds_free()`.

### Handles

The port is global: install it once, and it stays installed. Each identity is a handle from
`esp_rmaker_aws_sign_create()`. A handle holds the config copy, the credential host and one pooled
connection. `esp_rmaker_aws_sign_destroy()` releases only that handle, so two libraries in one
firmware do not interfere. A credentials struct filled through one handle is fetched again through
another. A call with a NULL handle returns `ESP_ERR_INVALID_ARG`. The check for a destroyed handle
is best-effort only, because the freed memory can be reused. Do not use a handle after
`esp_rmaker_aws_sign_destroy()`. `create()` returns
`ESP_ERR_INVALID_STATE` when no port is installed, and `ESP_ERR_NOT_SUPPORTED` when the port has no
`http` ops.

A library that only signs, for example with credentials from another provider, needs no handle. It
calls `esp_rmaker_aws_sign_port_install_default()` or installs its own port, and then calls
`esp_rmaker_aws_sign_sigv4()` or `esp_rmaker_aws_sign_presign_url()`.

Install the port in `app_main()`, before you start the tasks that use it. The install does not wait
for another install.

| `port_install()` returns | Meaning                                         | Next step                     |
|--------------------------|-------------------------------------------------|-------------------------------|
| `ESP_OK`                 | This port, or an identical one, is installed    | Continue                      |
| `ESP_ERR_INVALID_STATE`  | A different port is already installed           | Continue; signing still works |
| `ESP_ERR_NOT_FINISHED`   | Another task is installing now                  | Delay, then call it once more |
| Any other error          | The port is not valid, or `crypto.init` failed  | Fix the port                  |

`path` is the **raw** path. It is encoded once for the URL, and the signer applies the RFC 3986
encoding, including the rule that every non-S3 service double-encodes it. `params` are RAW
name/value pairs in any order; the component encodes and sorts them into the canonical query, and
sends the same string.

`region` is optional; NULL signs for the credential host's region.

`extra_headers` are signed as well as sent. A request with a payload gets `Content-Type:
application/json` unless `extra_headers` already carries one. `host`, `authorization` and the
`x-amz-date`, `x-amz-security-token` and `x-amz-content-sha256` headers come from the component, and
`extra_headers` must not carry them.

### Presigned URLs

`esp_rmaker_aws_sign_presign_url()` puts the signature in the query string instead of a header, for
a WebSocket handshake or a URL that another client fetches. It takes the same credentials as the
signer, plus `expires_sec` (1 to 604800) and an optional `wss` scheme.

```c
const esp_rmaker_aws_sign_query_param_t params[] = {
    { "X-Amz-ChannelARN", channel_arn }, { "X-Amz-ClientId", client_id },
};
esp_rmaker_aws_sign_presign_input_t in = {
    .scheme = "wss", .method = "GET", .host = signaling_host, .path = "/",
    .params = params, .params_count = 2, .expires_sec = 300,
    .access_key_id = creds.access_key_id, .secret_access_key = creds.secret_access_key,
    .session_token = creds.session_token, .region = region, .service = "kinesisvideo",
    .now_epoch_sec = time(NULL),
};
char *url = NULL;
if (esp_rmaker_aws_sign_presign_url(&in, &url) == ESP_OK) {
    /* connect to url */
    esp_rmaker_aws_sign_free(url);
}
```

The session token is signed by default. Set `token_after_signature` for AWS IoT MQTT over
WebSockets, which takes the token unsigned after the signature. An `s3` URL signs
`UNSIGNED-PAYLOAD`; other services sign the empty payload hash.

## Requirements

- ESP-IDF v5.1 or newer
- No RainMaker SDK dependency. `esp_rmaker_` is naming only.

## Porting

Every platform dependency enters through the function-pointer tables in `esp_rmaker_aws_sign.h`:
`mem`, `time`, `mutex`, `http`, `crypto`, `json` and `log`.
`esp_rmaker_aws_sign_port_install_default()` installs the ESP-IDF port from `port/esp/`;
`esp_rmaker_aws_sign_port_install()` installs your own and links none of it — the guarantee holds at archive-member granularity, so it does not need `--gc-sections`.
`CONFIG_ESP_RMAKER_AWS_SIGN_DISABLE_DEFAULT_PORT=y` drops the default port from the build outright.

A port's `perform()` receives one `esp_rmaker_aws_sign_http_receiver_t` — `hint`, `sink` and the
`ctx` they belong to. Report the declared response size to `hint` before streaming the body, which
is what lets the buffer be allocated once; pass 0 for a chunked reply.

**Do not call this component's API from a port operation.** Port operations run while the
component holds its locks, so a call from one deadlocks the calling task.

Take the defaults and swap one group when only one differs:

```c
esp_rmaker_aws_sign_port_config_t port = {
    .mem = esp_rmaker_aws_sign_esp_mem_ops,
    .crypto = esp_rmaker_aws_sign_esp_crypto_ops,
    .time = esp_rmaker_aws_sign_esp_time_ops,
    .mutex = esp_rmaker_aws_sign_esp_mutex_ops,
    .http = esp_rmaker_aws_sign_esp_http_ops,
    .json = esp_rmaker_aws_sign_esp_json_ops,
    .log = esp_rmaker_aws_sign_esp_log,
};
port.time.is_synced = my_sntp_state_fn;      /* a real answer instead of a threshold */
esp_rmaker_aws_sign_port_install(&port);
```

`rmaker_aws_sign_variables.cmake` publishes the platform-independent sources for a non-ESP-IDF build.
It needs libc and nothing else: `port/esp/crypto.c` (PSA Crypto) and `port/esp/json.c` (cJSON) are
reusable verbatim wherever those libraries are available, and the other five groups are small.

The crypto port is written against **PSA Crypto** (`psa_hash_*`, `psa_mac_compute`) rather than the
legacy `mbedtls_sha256_*` / `mbedtls_md_hmac` APIs, which mbedtls 4.x — ESP-IDF v6.0 and newer —
removed. Its `init` member calls `psa_crypto_init()` at port install, so an application need not.
A backend with one-time setup puts it in `crypto.init`; the install runs it before any task can sign.

**A replacement `crypto` backend must pass the `[aws_sign_crypto]` vectors first.** That group ports
fully specified algorithms — FIPS 180-4 and RFC 2104 — so conformance is pass/fail, and a backend
that fails it produces signatures AWS rejects with nothing but `SignatureDoesNotMatch` to go on. A
replacement `json` backend must likewise pass `[aws_sign_json]`: cJSON needed three checks added
around it (a duplicate requested key refused, a non-string value refused, and an escape that decodes
to NUL rejected before the parse), and another library will need its own.

## Constraints

- **Signing is cheap; the TLS handshake is not.** `esp_rmaker_aws_sign_sigv4()` uses under 1 KB of
  stack, so a sign-only caller can run on a small task. Budget **6–8 KB** for tasks that call
  `esp_rmaker_aws_sign_creds_refresh()` or `esp_rmaker_aws_sign_send_request()`. The ESP port does
  no flash access, so a SPIRAM stack works. Read the certificate and key from flash on an
  internal-RAM stack, before `esp_rmaker_aws_sign_create()`.
- **All APIs are synchronous and blocking.** Call them from a dedicated task, never from an event or
  MQTT callback. On one handle, credential fetches run one at a time, and so do signed requests.
- **A credentials struct is not locked.** Use one struct for each role alias. Tasks can share one
  struct only when every task uses it through `esp_rmaker_aws_sign_send_request()` on the same
  handle. Otherwise, add your own lock.
- **Time sync is the caller's responsibility.** `x-amz-date` must be within ~15 min of AWS server
  time. The clock check in `esp_rmaker_aws_sign_creds_refresh()` guards against misuse — it returns
  `ESP_ERR_INVALID_STATE` and performs no network I/O — but it is not a substitute for waiting on
  SNTP. `esp_rmaker_aws_sign_sigv4()` is deliberately not gated: it trusts `now_epoch_sec` verbatim.
- **Header limit is 16**, including `host`, `x-amz-date`, `x-amz-security-token` and, for
  `esp_rmaker_aws_sign_send_request()`, `x-amz-content-sha256`. Exceeding it is an error, never a
  silent truncation.
- **Quoted-string header values are not supported.** SigV4's whitespace-collapse exemption for text
  inside double quotes is not implemented.
- **A path must start with `/`.** For every service except S3, the signer removes `.`, `..` and
  empty segments from the canonical URI, as SigV4 requires. The URL keeps the path as given.
- **A port must be installed before any API is called**, the signer included. Without `http` ops the
  signer works and `esp_rmaker_aws_sign_create()` returns `ESP_ERR_NOT_SUPPORTED`.
- **Memory handed back is port-allocated.** Release it with the matching `_free()`, or
  `esp_rmaker_aws_sign_free()` for `esp_rmaker_aws_sign_parse_region_from_host()` and
  `esp_rmaker_aws_sign_presign_url()`, never with libc `free()`.

## Tests

`test_apps/` holds the suites: `[aws_sign_crypto]` (FIPS 180-4 and RFC 4231),
`[aws_sign_sigv4]` (the signature, query and presign vectors), `[aws_sign_json]`, `[aws_sign_creds]`,
`[aws_sign_http]` and `[aws_sign_port]`. CI also runs them on the `linux` target, which skips the
one `[aws_sign_http]` test that needs a real loopback socket. `tools/sigv4_ref.py` is an independent implementation of
the signing spec that reproduces AWS's published `get-vanilla`, S3 GET object and S3 presigned URL
answers and generates the vectors; run it first when a new
service or path shape needs signing, then make the C match.
