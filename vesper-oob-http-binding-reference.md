# VESPER OOB - Concrete HTTP Binding (Extracted Reference)

This file preserves the concrete HTTPS/REST interface specification that was
removed from draft-wendt-stir-vesper-oob-03 when the document was restructured
to describe the OOB mechanism abstractly (sequence + properties) rather than
prescribe a specific API, consistent with the non-prescriptive posture of
RFC 8816 and the borrowed publish/retrieve/authorization mechanism.

It is retained here as an OPTIONAL concrete HTTP binding that implementers MAY
adopt. It is not part of the draft. Nothing here is normative for VESPER OOB.

---

# HTTPS Interface Specification

The interface design is conceptually aligned with the interface model described in ATIS-1000105 Section 7. It supports two categories of HTTPS methods:

General Operations:

These required endpoints enable basic VESPER-OOB publish and retrieval functions:

- GET /health - check service availability
- POST /passports/{DEST}/{ORIG} - publish one or more signed PASSporTs, optionally with a 'response_uuid' for Connected Identity
- GET /passports/{DEST}/{ORIG} - retrieve published PASSporTs and optionally discover an associated 'response_uuid'

Connected Identity Extensions:

These optional endpoints are used if a `response_uuid` was included in the publish operation and the recipient supports Connected Identity:

- POST /respond/{UUID} - the called party submits a 'rsp' PASSporT
- GET /passports/response/{UUID} - the caller polls for the response
- GET /passports/response/stream/{UUID} - Server-Sent Events (SSE) push interface (optional)
- wss://.../stream/respond/{UUID} - WebSocket push delivery (optional)

All endpoints MUST be served over HTTPS. All endpoints that expose PASSporTs, Connected Identity UUIDs, or response PASSporTs MUST require authentication via Access JWT as defined in the Common Access JWT section. The GET /health endpoint does not require authentication. PPS operators SHOULD additionally enforce rate-limits and access-control policies.

Server certificates SHOULD be validated using standard PKIX procedures. HTTP Strict Transport Security (HSTS) MAY be used by PPS operators to enforce HTTPS usage.

## Common Access JWT

All PPS interfaces that require authorization MUST support Access JWTs signed using the `ES256` algorithm and validated against trusted VESPER delegate certificates. These tokens establish caller or responder identity and intent.

### Access JWT Header

~~~ json
{
  "alg": "ES256",
  "x5c": [
    "MIIB3TCCAYOgAwIBAgIUUjF7Jq9kYfU12nJkBA==",
    "IUUjF7Jq9kYfU12nJkBAMIIB3TCCAYOgAwIBAg=="
  ]
}
~~~

- 'alg': MUST be "ES256" as required by STIR PASSporT and VESPER.
- 'x5c': An array of base64-encoded certificates representing the end-entity delegate certificate and any intermediate certificates with an optionally included root certificate. These MUST be validated against the trust anchors defined in the certificate policy defined in RFC8226.

### Access JWT Claims

The Access JWT payload MUST contain the following claims:

| Claim         | Description                                                      |
|---------------|------------------------------------------------------------------|
| 'iat'         | Issued-at timestamp (Unix time). MUST be recent (< 5 min skew). |
| 'exp'         | Expiration timestamp for the token.                              |
| 'jti'         | Unique token ID for replay prevention and audit.                 |
| 'action'      | Operation intent: "publish", "retrieve", or "respond".           |
| 'aud'         | PPS hostname. MUST match the target server.                      |
| 'iss'         | SPC or TN of the signer. MUST match TNAuthList in cert.          |
| 'sub'         | SPC or TN of the subscriber on whose behalf the action is taken. |
| 'orig'        | Object with TN/URI of the originating party.                     |
| 'dest'        | Object with TN/URI of the destination party.                     |
| 'passports'   | OPTIONAL. See below for digest definition.                       |
| 'rsp_passport'| OPTIONAL. See below for digest definition.                       |

The 'passports' claim, when present for a "publish" action, MUST contain the base64url-encoded SHA-256 hash of the JCS (RFC8785) canonicalization of the complete JSON request body object (i.e., the object containing the `passports` array). The 'rsp_passport' claim, when present for a "respond" action, MUST contain the base64url-encoded SHA-256 hash of the JCS (RFC8785) canonicalization of the complete JSON request body object (i.e., the object containing the `rsp_passport` field). Hash values MUST use base64url encoding without padding as defined in RFC 4648 Section 5.

Note: The TNAuthList in a VESPER delegate certificate may contain TN entries, SPC entries, or both. In the common case where an entity signs for its own telephone numbers, `iss` and `sub` will be the same value and correspond to a TN or SPC in the TNAuthList, as the signing entity and the telephone number holder are the same party. In platform or delegated deployments, `iss` may identify an SPC-authorized signing entity while `sub` identifies the subscriber's TN, both of which are covered by the certificate's TNAuthList.

#### Examples

Publish Token (Calling Party):

~~~ json
{
  "iat": 1693590000,
  "exp": 1608048425,
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "action": "publish",
  "aud": "pps.example.net",
  "iss": "12013776051",
  "sub": "12013776051",
  "orig": { "tn": "12013776051" },
  "dest": { "tn": ["19032469103"] },
  "passports": "sha256-XyZabc123..."
}
~~~

Retrieve Token (Verifying Called Party):

~~~ json
{
  "iat": 1693590100,
  "exp": 1693590400,
  "jti": "550e8400-e29b-41d4-a716-426655440002",
  "action": "retrieve",
  "aud": "pps.example.net",
  "iss": "19032469103",
  "sub": "19032469103",
  "orig": { "tn": "12013776051" },
  "dest": { "tn": ["19032469103"] }
}
~~~

Respond Token (Called Party responding with Connected Identity):

~~~ json
{
  "iat": 1693590050,
  "exp": 1693590400,
  "jti": "550e8400-e29b-41d4-a716-426655440001",
  "action": "respond",
  "aud": "pps.example.net",
  "iss": "19032469103",
  "sub": "19032469103",
  "orig": { "tn": "12013776051" },
  "dest": { "tn": ["19032469103"] },
  "rsp_passport": "sha256-AbCdEf123..."
}
~~~

### Validation Rules

The PPS MUST validate the Access JWT as follows:

- Signature: Must be signed with ES256 using a VESPER delegate certificate that chains to a trusted STI root.
- Certificate: The certificate in 'x5c' MUST match the 'iss'/'sub' TN and contain valid TNAuthList entries.
- Time Validity: 'iat' MUST be recent (within an allowed freshness window, e.g., 5 minutes).
- Audience: 'aud' MUST match the target PPS domain.
- Claims Match: The 'orig' and 'dest' claims MUST match the HTTP path parameters.
- Digest Integrity: If the 'passports' or 'rsp_passport' claim is present, its value MUST equal the base64url-encoded SHA-256 hash computed over the JCS (RFC8785) canonicalization of the complete JSON request body. Both parties MUST canonicalize the full request body object before hashing. The encoding of the hash value MUST use base64url without padding as defined in RFC 4648 Section 5.

### Additional Security

- PPS SHOULD reject expired, reused, or improperly scoped JWTs.
- JWT replay prevention SHOULD be enforced using the jti field and short TTLs. The PPS MUST cache recent jti values and MUST reject re-use within the configured window.
- Tokens MUST be scoped per transaction; long-lived JWTs MUST NOT be used.

---

## API Method Definitions

### Method: 'GET /health'

#### Request Definition

~~~ http
Method: GET
Path: /health
Authentication: None required
~~~

#### Response Definition

200 OK - Service operational
503 Service Unavailable - Service not operational
Body (optional):

~~~ json
{
  "status": 200,
  "message": "OK"
}
~~~

### Publish Method: POST /passports/{DEST}/{ORIG}

This method allows the calling party to publish one or more signed PASSporTs associated with a specific ORIG and DEST pair. The PPS MAY optionally return a `response_uuid` for Connected Identity.

PASSporTs and Connected Identity response PASSporTs SHOULD be retained only for a short period of time unless longer retention is explicitly required by policy.

Note: ATIS-1000105 defines a "re-publish" action for forwarding PASSporTs between CPSs. Because VESPER OOB uses a transparent discovery model based on STI-CT log monitoring rather than bilateral CPS-to-CPS communication, re-publishing is not required. CPS implementations conforming to this specification are not required to support the re-publish action or the associated "token" fields defined in ATIS-1000105. However, this specification is designed to be compatible with deployments that support both VESPER OOB and ATIS-1000105.

#### Request Definition

~~~ http
Method: POST
Path: /passports/{DEST}/{ORIG}
Authentication: Access JWT with "action": "publish"
~~~

#### Request Headers

~~~ http
Content-Type: application/json
Authorization: Bearer <Access JWT>
~~~

The server SHOULD support an Idempotency-Key request header (I-D.ietf-httpapi-idempotency-key-header). When present, repeated requests with the same key MUST return the original result without creating duplicate records.

#### Request Parameters

DEST: Canonicalized and percent-encoded destination telephone number or URI.
ORIG: Canonicalized and percent-encoded originating telephone number or URI.

Canonicalization of TNs follows RFC8224 and percent encoding of URIs follows RFC3986.

Note: The path ordering places {DEST} before {ORIG} to align with the lookup pattern used by the called party, which typically knows its own number (DEST) and resolves PASSporTs based on the calling party (ORIG). The PPS MUST validate that the `orig` and `dest` claims in the Access JWT match the {ORIG} and {DEST} path parameters respectively; a mismatch MUST result in a 403 Forbidden response.

#### Request Body

The request body is a JSON object with the following field:

- passports: REQUIRED. An array of one or more PASSporT strings signed by the calling party. Multiple PASSporTs MAY be included when the authentication service issues PASSporTs with different `ppt` types (e.g., a base `shaken` PASSporT alongside a `div` or `rcd` PASSporT) for the same call. All PASSporTs in the array MUST share the same `orig`, `dest`, and `iat` values and MUST be signed by the same delegate certificate.

Authorization JWT Requirements:

The Access JWT for this method MUST include:

- "action": "publish"

All other validation requirements are defined in Common Access JWT.

#### Example Request

~~~ http
POST /passports/19032469103/12013776051 HTTP/1.1
Host: pps.example.com
Authorization: Bearer <Access JWT>
Content-Type: application/json

{
  "passports": [
    "eyJhbGciOiJFUzI1NiIsIn..."
  ]
}
~~~

#### Response Definition

Success Codes

~~~ http
201 - Created if the PASSporTs were successfully published.
~~~

Failure Codes

~~~ http
400 - Bad Request if required fields are missing or malformed
401 - Unauthorized if authentication fails
403 - Forbidden if certificate constraints are not met
429 - Too Many Requests if rate-limited
5xx errors (e.g., 503 Service Unavailable)
~~~

Responses MUST use status codes defined in RFC6585 and SHOULD be informative when possible.

If the server supports Connected Identity, the response body MAY include a `response_uuid` that the called party can use in follow-up Connected Identity methods. This UUID (RFC4122) is generated by the PPS and serves as a transaction-specific identifier for subsequent API calls.

#### Example Response

~~~ http
HTTP/1.1 201 Created
Content-Type: application/json

{
  "status": 201,
  "message": "Created",
  "response_uuid": "123e4567-e89b-12d3-a456-426614174000"
}
~~~

#### Response Body Fields

- `status`: HTTP status code indicating result of publish request (e.g., 201 for success).
- `message`: A human-readable message describing the outcome of the request.
- `response_uuid`: (Optional) A UUID (RFC4122) generated by the PPS for Connected Identity. Returned only if the PPS supports Connected Identity response workflows.

#### Example Success and Error Responses

Success Response (201 Created):

~~~ http
HTTP/1.1 201 Created
Content-Type: application/json

{
  "status": 201,
  "message": "Created",
  "response_uuid": "123e4567-e89b-12d3-a456-426614174000"
}
~~~

Error Response (400 Bad Request):

~~~ http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "status": 400,
  "error": "Missing required field: passports"
}
~~~

Error Response (401 Unauthorized):

~~~ http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "status": 401,
  "error": "Access JWT is invalid or expired"
}
~~~

### Retrieve Method: GET /passports/{DEST}/{ORIG}

This method allows the called party to retrieve PASSporTs published by the originating party for a given ORIG/DEST combination.

#### Request Definition

~~~ http
Method: GET
Path: /passports/{DEST}/{ORIG}
Authentication: Access JWT with "action": "retrieve"
~~~

#### Request Headers

~~~ http
Authorization: Bearer <Access JWT>
~~~

#### Request Parameters

- DEST: Percent-encoded and canonicalized destination telephone number or URI, representing the final called party after any retargeting.
- ORIG: Percent-encoded and canonicalized calling party TN or URI, typically from the SIP From or P-Asserted-Identity header.

Canonicalization of TNs follows RFC8224 and percent encoding of URIs follows RFC3986.

Note: The path ordering places {DEST} before {ORIG} to align with the lookup pattern used by the called party, which typically knows its own number (DEST) and resolves PASSporTs based on the calling party (ORIG). The PPS MUST validate that the `orig` and `dest` claims in the Access JWT match the {ORIG} and {DEST} path parameters respectively; a mismatch MUST result in a 403 Forbidden response.

#### Authorization JWT Requirements

The JWT used to authorize this request MUST include:

- "action": "retrieve"

All other JWT validation requirements are defined in Common Access JWT and MUST also be enforced by the PPS.

#### Prerequisite Check

Before accepting a Connected Identity response, the PPS SHOULD verify that the PASSporT associated with the given `response_uuid` was previously retrieved by a party whose `iss` claim matches the `dest` TN of the original transaction. This ensures that the responding party has had the opportunity to validate the originating PASSporT before asserting its own identity. If the PPS enforces this check and no prior retrieval has occurred, it SHOULD return 409 Conflict with a descriptive error indicating that retrieval must precede response submission.

#### Response Definition

Success:

~~~
200 OK - PASSporT(s) retrieved successfully
~~~

Failure:

~~~
401 Unauthorized - JWT missing or invalid
403 Forbidden - Certificate constraints violated
404 Not Found - No PASSporTs available
429 Too Many Requests - Rate limits exceeded
503 Service Unavailable - PPS temporarily unavailable
~~~

Status codes MUST follow RFC6585. On 5xx failures, retrying another PPS endpoint MAY be allowed.

Response Body (on success):

~~~ json
{
  "passports": [
    "eyJhbGciOiJFUzI1NiIsIn..."
  ],
  "response_uuid": "123e4567-e89b-12d3-a456-426614174000"
}
~~~

- `passports`: An array of one or more PASSporT strings published by the originating party, in compact JWS serialization format as per RFC8225.
- `response_uuid`: OPTIONAL. If present, provides the Connected Identity transaction UUID (RFC4122) to which the called party can submit an identity response PASSporT using the appropriate API method. This value is provided only if included in the corresponding publish operation.

#### Example Request

~~~ http
GET /passports/19032469103/12013776051 HTTP/1.1
Host: pps.example.com
Authorization: Bearer <Access JWT>
~~~

#### Example Response

~~~ http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "passports": [
    "eyJhbGciOiJFUzI1NiIsIn..."
  ],
  "response_uuid": "123e4567-e89b-12d3-a456-426614174000"
}
~~~

#### Response Body Fields

- `passports`: Array of PASSporT strings published by the originating party, encoded in compact JWS serialization.
- `response_uuid`: (Optional) UUID (RFC4122) that identifies a Connected Identity response transaction. Provided only if the PPS returned it during publish.

### Respond Method: POST /respond/{UUID}

This method allows the called party to submit a response PASSporT (rsp_passport) asserting their identity in a Connected Identity exchange. The UUID (RFC4122) corresponds to the `response_uuid` originally returned by the PPS during the publish operation.

#### Request Definition

~~~ http
Method: POST
Path: /respond/{UUID}
Authentication: Access JWT with "action": "respond"
~~~

#### Request Body

~~~ json
{
  "rsp_passport": "eyJhbGciOiJFUzI1NiIsIn..."
}
~~~

- rsp_passport: REQUIRED. The PASSporT signed by the called party delegate certificate for Connected Identity.

#### Authorization JWT Requirements

The JWT used to authorize this request MUST include:

- "action": "respond"

#### Response Definition

Success:

~~~
201 Created - The Connected Identity response was accepted.
~~~

Failure:

~~~
401 Unauthorized - JWT missing or invalid.
403 Forbidden - Certificate constraints violated.
404 Not Found - UUID not found or expired.
409 Conflict - A response has already been submitted.
429 Too Many Requests - Rate limits exceeded.
503 Service Unavailable - PPS temporarily unavailable.
~~~

Status codes MUST follow RFC6585. Connected Identity response PASSporTs SHOULD be retained only for a short period unless longer retention is explicitly required by policy.

### Retrieve Response Method: GET /passports/response/{UUID}

This method allows the originating (calling) party to retrieve a Connected Identity response PASSporT, if one has been submitted by the called party. The UUID in this path is the same value (`response_uuid`) previously provided by the PPS in the response to the `POST /passports/{DEST}/{ORIG}` method.

#### Request Definition

~~~ http
Method: GET
Path: /passports/response/{UUID}
Headers: Authorization: Bearer <JWT>
~~~

#### Response Body

~~~ json
{
  "rsp": {
    "passport": "eyJhbGciOiJFUzI1NiIsIn..."
  }
}
~~~

### Retrieve Response Push Methods (Optional)

The PPS MAY support real-time delivery of Connected Identity responses via push interfaces as an alternative to polling.

#### Server-Sent Events (SSE)

~~~
GET /passports/response/stream/{UUID}
Accept: text/event-stream
Authorization: Bearer <Access JWT>
~~~

The SSE endpoint uses the same Access JWT authentication as the polling GET endpoint. The JWT MUST include `"action": "retrieve"` and the `iss` claim MUST match the originating party of the transaction. The PPS MUST validate the JWT before initiating the event stream.

#### WebSocket

~~~
wss://pps.example.net/stream/respond/{UUID}
~~~

Because the WebSocket upgrade request does not support the Authorization header in all client implementations, the Access JWT MUST be conveyed using one of the following mechanisms, listed in order of preference:

1. The `Sec-WebSocket-Protocol` subprotocol negotiation, using the format `access_token.<JWT>`.
2. A query parameter `?token=<JWT>` on the connection URI. When this method is used, PPS operators MUST ensure the token is not logged in access logs.
3. An initial text frame sent immediately after connection establishment, containing the Access JWT. The PPS MUST NOT transmit any response data until the JWT has been received and validated.

The PPS MUST close the WebSocket connection with status code 1008 (Policy Violation) if the JWT is missing, invalid, or unauthorized.

Both push interfaces MUST enforce the same authorization constraints as the polling GET endpoint: only the authenticated originating party of the transaction (as identified by `iss`) is permitted to receive the response.

---

# Example VESPER OOB Request/Response Flow

This example illustrates a full transaction using the Connected Identity UUID-based pattern.

## Calling Party Publishes a PASSporT

~~~ http
POST /passports/19035551234/12015550100 HTTP/1.1
Host: pps.example.net
Content-Type: application/json
Authorization: Bearer <jwt-from-calling-party>
~~~

Body:

~~~
{
  "passports": [
    "eyJhbGciOiJFUzI1NiIsIn..."
  ]
}
~~~

Response:

~~~ http
HTTP/1.1 201 Created
Content-Type: application/json

{
  "status": 201,
  "message": "Created",
  "response_uuid": "123e4567-e89b-12d3-a456-426614174000"
}
~~~

## Called Party Retrieves PASSporT and Extracts response_uuid

~~~ http
GET /passports/19035551234/12015550100 HTTP/1.1
Host: pps.example.net
Authorization: Bearer <jwt-from-called-party>
~~~

Response:

~~~
{
  "passports": [
    "eyJhbGciOiJFUzI1NiIsIn..."
  ],
  "response_uuid": "123e4567-e89b-12d3-a456-426614174000"
}
~~~

## Called Party Submits a Connected Identity `rsp` PASSporT

~~~ http
POST /respond/123e4567-e89b-12d3-a456-426614174000 HTTP/1.1
Host: pps.example.net
Content-Type: application/json
Authorization: Bearer <jwt-from-called-party>
~~~

Body:

~~~ json
{
  "rsp_passport": "eyJhbGciOiJFUzI1NiIsIn..."
}
~~~

Response:

~~~ http
HTTP/1.1 201 Created
Content-Type: application/json

{"status":201,"message":"Connected Identity Stored"}
~~~

## Calling Party Polls for the `rsp` PASSporT

~~~ http
GET /passports/response/123e4567-e89b-12d3-a456-426614174000 HTTP/1.1
Host: pps.example.net
Authorization: Bearer <jwt-from-calling-party>
~~~

Response:

~~~ json
{
  "rsp": {
    "passport": "eyJhbGciOiJFUzI1NiIsIn..."
  }
}
~~~
