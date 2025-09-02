---
###
# VESPER Out‑of‑Band (OOB)
###
title: "VESPER OOB"
abbrev: "VESPER OOB"
category: std

docname: draft-wendt-stir-vesper-oob-00
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: AREA
workgroup: WG Working Group
keyword:
- stir
- certificates
- delegate certificates
- oob
venue:
  group: "Secure Telephone Identity Revisited"
  type: "Working Group"
  mail: "stir@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/stir/"
  github: "appliedbits/draft-wendt-stir-vesper-oob"
  latest: "https://github.com/appliedbits/draft-wendt-stir-vesper-oob"

author:
 -
    fullname: Chris Wendt
    organization: Somos Inc.
    email: chris@appliedbits.com
 -
    fullname: Rob Sliwa
    organization: Somos Inc.
    email: robjsliwa@gmail.com

normative:
  RFC3261:
  RFC3986:
  RFC6585:
  RFC8224:
  RFC8225:
  RFC8226:
  RFC8816:
  RFC9060:
  RFC9447:
  I-D.wendt-stir-certificate-transparency:
  I-D.wendt-stir-vesper:
  I-D.wendt-stir-vesper-use-cases:
  I-D.sliwa-stir-cert-cps-ext:
  I-D.sliwa-stir-oob-transparent-discovery:

informative:
  ATIS-1000096: 
    title: "ATIS-1000096 - Technical Report on SHAKEN Out-of-Band PASSporT Transmission Involving TDM-SIP Interworking"
    author: 
      - org: ATIS
    target: https://access.atis.org/apps/group_public/download.php/52450/ATIS-1000096.pdf

--- abstract

This document describes a mechanism for delivering authenticated telephone call identity information using the VESPER framework in environments where SIP signaling is unavailable or unsuitable. By supporting an out-of-band (OOB) transport model, this approach enables entities to publish and retrieve signed PASSporT assertions independent of end-to-end delivery within SIP-based VoIP networks. These PASSporTs are signed with delegate certificates that were authorized for issuance by corresponding authority tokens, which represent the trust and validation of telephone number control and related claim information. Transparency features ensure that these authorizations are publicly auditable and cryptographically provable, supporting a higher standard of trust. The OOB mechanism serves as an alternative delivery path for PASSporTs in cases where end-to-end in-band SIP delivery is not possible, enabling verifiers to confirm the association between the originating telephone number and the identity asserting authority as part of the broader VESPER trust framework.

--- middle

# Introduction

The STIR framework enables the signing and verification of telephone calls using PASSporT objects carried in SIP {{RFC3261}}. However, there are scenarios where SIP-based in-band transmission is not feasible, such as legacy TDM interconnects or where intermediary network elements strip SIP Identity headers. {{RFC8816}} addresses this generally for STIR by defining an Out-of-Band (OOB) delivery model.

The VESPER framework {{I-D.wendt-stir-vesper}} extends the STIR framework by introducing support for vetted delegate certificates using authority tokens and certificate transparency logs and monitoring to enhance reliability and trust for the delegation of telephone number specific certificates and the associated claims authorized to be made by the use of those certificates for signed PASSporTs. The use cases motivating these enhancements are outlined in {{I-D.wendt-stir-vesper-use-cases}}.

This document describes how to expand the VESPER framework to use an out-of-band delivery mechanism corresponding to the model described in {{RFC8816}}. The VESPER framework defines how delegate certificates are issued based on authority tokens that attest to the vetting and authorization of the entity to use a telephone number and assert other related claim information. This specification extends this to enable authorized delegate certificate holders, who sign calls via a STIR Authentication Service, to deliver PASSporTs containing authorized, verifiable claims over a non-SIP-based path. These PASSporTs can be retrieved and validated by a STIR Verification Service, similar to SIP-based STIR as defined in {{RFC8224}}, thereby maintaining continuity of trust across heterogeneous networks.

OOB delivery is critical in extending the utility of STIR to networks where SIP identity headers cannot be delivered end-to-end. It provides a verifiable alternative path for transmitting PASSporTs and proving the originating telephone number's association to the signing identity.

The Vesper OOB delivery model assumes a one-way publish-and-retrieve interface based on the open discovery model. This document extends the concepts in {{RFC8816}} to specifically define an HTTPS-based interface for publishing and retrieving VESPER PASSporTs. It utilizes the following: 

- A mechanism for announcing the associated OOB Call Placement Services (CPSs) using the CPS URI extension defined in {{I-D.sliwa-stir-cert-cps-ext}}.
- A discovery mechanism for OOB endpoints based on {{I-D.sliwa-stir-oob-transparent-discovery}} with the corresponding Vesper requirement to utilize and verify STI certificate transparency receipts with delegate certificates used in Vesper OOB.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

VESPER: Verifiable Entity STIR Passport Entity Representation {{I-D.wendt-stir-vesper}}.

PASSporT: Personal Assertion Token as defined in {{RFC8225}}.

Delegate Certificate: A certificate issued to an enterprise or user entity asserting right-to-use for a telephone number, based on an authority token, defined in {{RFC9060}}.

Authority Token: A signed assertion that authorizes the issuance of a delegate certificate and represents the vetting of a subject's control over a telephone number and any associated claims defined in {{RFC9447}}.

CPS URI: Call Placement Service (CPS) URI extension in X.509 certs {{I-D.sliwa-stir-cert-cps-ext}}.

CPS Discovery: Defines the use of STI certificate transparency log monitoring and CPS URI extension in certificates for announcing CPS locations for certificates {{I-D.sliwa-stir-oob-transparent-discovery}}.

# Vesper OOB Architectural Overview

The VESPER OOB architecture consists of three main functional components that work together to enable the out-of-band signing, publishing, discovery, and verification of PASSporTs using a trust framework based on delegate certificates and transparency mechanisms. These components interact across SIP and HTTPS protocols to support both simulataneous and parallel in-band and out-of-band delivery of call identity information, ensuring interoperability across a variety of telephony related network environments. Figure 1 illustrates the flow of identity data between the authentication service, the out-of-band Call Placement Service (CPS), and the verification service.

~~~
        +--------------------+  Send SIP INVITE /w Identity
        |   Authentication   |  Header Field (RFC8824/VESPER AS)
        |     Service        |-------------------+
        |  (Calling Party)   |                   |
        +---------+----------+                   |
                  |                              |
                  | 1. Publish PASSporT with     |
                  |    Delegate Certificate      |
                  v                          .~~~~~~~~~~.
        +---------+----------+           .-''             '-.
        |        CPS         |        ,.'   SIP-based VoIP  '.
        |      (HTTPS)       |       /        Routing        |      
        +---------+----------+      |         Network       /
                  ^                  '.___..~~~~~~..______.'
                  |                              |
                  | 2. Retrieve PASSporT         |
                  |                              |
        +---------+----------+                   |
        |    Verification    |                   |
        |      Service       |<------------------+
        |   (Called Party)   |  Receive SIP INVITE /w Identity
        +--------------------+  Header Field (RFC8824/VESPER VS)
~~~
Figure 1 - Architecture showing both in-band and out-of-band PASSporT delivery

# HTTPS Interface Specification

The interface design is conceptually aligned with the interface model described in {{ATIS-1000096}} Section 7, and supports the following HTTPS methods:

- GET /health endpoint for CPS service monitoring.
- POST /passports/{DEST}/{ORIG} to publish a signed PASSporT.
- GET /passports/{DEST}/{ORIG} to retrieve the PASSporT based on telephone number and orig.

All endpoints MUST be served over HTTPS. The POST endpoint MUST require authentication. The GET endpoint SHOULD be unauthenticated, but MUST be rate-limited and optionally support authorization policies for access control.

The detailed definitions of each of the methods follows.

## GET /health

The HTTP GET health check endpoint allows relying parties to determine the operational readiness of the CPS service.

Request:

Method: GET
URI: /health

Response:

- If the CPS is fully operational—able to process both publish and retrieve requests for PASSporTs, it MUST return an HTTP status code 200 OK.
- If the CPS is unable to process either publish or retrieve requests, it MUST return an HTTP error status code greater than 399, in accordance with RFC 6585 (e.g., 503 Service Unavailable).
- The response MAY include a diagnostic payload or status indicator, but no body is required.

This endpoint is intended for availability monitoring and MUST be accessible without authentication.

Example Request:

~~~
GET /health HTTP/1.1
Content-Length: 0
Host: cps.example.com
~~~

Example Response: 

~~~`
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 29

{"status":200,"message":"OK"}
~~~

## POST /passports/{DEST}/{ORIG}

The HTTPS interface for publishing PASSporT(s) requires a POST request to the path /passports/{DEST}/{ORIG}. The path parameters MUST be substituted as follows:

DEST: The percent-encoded and canonicalized destination telephone number (TN) or URI, representing the called party after any retargeting. If a valid telephone number is not available, the called URI (e.g., "urn:service:sos") MAY be used instead, encoded per RFC 3986.

ORIG: The percent-encoded and canonicalized calling party TN or URI, typically obtained from the SIP From or P-Asserted-Identity header. Canonicalization of telephone numbers follows the procedures in {{RFC8224}}.

### Request definition

Method: POST
Path: /passports/{DEST}/{ORIG}
Headers:

- Content-Type: application/json
- Authorization: Bearer /<JWT/>
- Body (example for a standard publish request):

~~~ json
{
  "passports": [
    "eyJhbGciOiJFUzI1NiIsIn..."
  ]
}
~~~

If the publishing request is being made by an STI-CPS for the purpose of re-publishing, the request body MUST also include a "token" key containing the original service provider's authentication JWT.

#### Authorization JWT Requirements

The Authorization header MUST include a JWT access token signed with an ES256 algorithm using a valid delegate certificate that chains to a trusted STI root. The JWT MUST meet the following conditions:

The "passports" claim MUST include the SHA-256 digest (base64-encoded, prefixed with sha256-) of the canonicalized form of the "passports" array in the request body, using JSON Canonicalization Scheme (JCS, RFC 8785).
The sub and iss claims MUST match the SPC in the TNAuthList of the signing certificate.

#### Example JWT access token:

Header:

~~~ json
{
  "alg": "ES256",
  "x5u": "https://certs.example.net/delegate.crt"
}
~~~

Payload (example for a publish request):

~~~ json
{
  "iat": 1693590000,
  "action": "publish",
  "passports": "sha256-XyZabc123...",
  "sub": "12013776051",
  "iss": "12013776051",
  "aud": "cps.example.net",
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "dest": {
    "tn": ["19032469103"]
  },
  "orig": {
    "tn": "12013776051"
  }
}
~~~

### Response definition

Success:

- 201 - Created if the PASSporTs were successfully published (even if republish propagation is still pending).

Failure:

- 400 - Bad Request if required fields are missing or malformed
- 401 - Unauthorized if authentication fails
- 403 - Forbidden if certificate constraints are not met
- 429 - Too Many Requests if rate-limited
- 5xx errors (e.g., 503 Service Unavailable) - if the server cannot process the request

Responses MUST use status codes defined in RFC 6585 and SHOULD be informative when possible.

Note: {{ATIS-1000096}} supports a "re-publish" action, because the VESPER-OOB discovery mechanism is different and re-publishing PASSporTs is not required for VESPER-OOB, CPSs that support this specification should not support the initiation of this action or otherwise communicate to other CPSs supporting this specification 

### Example Request:

~~~
POST /passports/19032469103/12013776051 HTTP/1.1
Content-Type: application/json
Content-Length: 423
Host: cps.example.com
Authorization: Bearer
eyJhbGciOiJFUzI1NiIsIng1dSI6Imh0dHBzOi8vY2VydGlmaWNhdGVzLmV4YW1wbGU
uY29tL2V4YW1wbGUuY3J0In0.eyJpYXQiOjE2OTM1OTAwMDAsImFjdGlvbiI6InB1Ym
xpc2giLCJwYXNzcG9ydHMiOiJzaGEyNTYtWU80SHEveEU2bWtDZXVQb1lZY2s1UHQ2d
kFDbWZiek5mZGk2YWVxOTVkQT0iLCJzdWIiOiIxMjAxMzc3NjA1MSIsImlzcyI6IjEy
MDEzNzc2MDUxIiwiYXVkIjoiY3BzLmV4YW1wbGUubmV0IiwianRpIjoiNTUwZTg0MDA
tZTI5Yi00MWQ0LWE3MTYtNDQ2NjU1NDQwMDAwIiwiZGVzdCI6eyJ0biI6WyIxOTAzMj
Q2OTEwMyJdfSwib3JpZyI6eyJ0biI6IjEyMDEzNzc2MDUxIn19.8_1lwoansAWNV7Jb
VNMCS_jqnfTpwLl28iOUdYIWctEZ4EBDQgB73u-GOU3ePgN1vWJHGS9IN9NUKC0i2S_
5kw

{"passports":["eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBh
c3Nwb3J0IiwieDV1IjoiaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMuZXhhbXBsZS5jb20vZXh
hbXBsZS5jcnQifQ.eyJhdHRlc3QiOiJBIiwiZGVzdCI6eyJ0biI6WyIxOTAzMjQ2OTE
wMyJdfSwiaWF0IjoxNTg0OTgzNDAyLCJvcmlnIjp7InRuIjoiMTIwMTM3NzYwNTEifS
wib3JpZ2lkIjoiNGFlYzk0ZTItNTA4Yy00YzFjLTkwN2ItMzczN2JhYzBhODBlIn0.E
MfXHyowsI5s73KqoBzJ9pzrrwGFNKBRmHcx-YZ3DjPgBe4Mvqq9N-bThN1_HTWeSvbr
uAyet26fetRL1_bn1g"]}
~~~

Example Private Key used: 

-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----

### Example Response:

~~~
HTTP/1.1 201 Created
Content-Type: application/json
Content-Length: 34
{"status":201,"message":"Created"}
~~~

## GET /passports/{DEST}/{ORIG}

The HTTPS interface for retrieving PASSporT(s) is accessed via a GET request to the path /passports/{DEST}/{ORIG}. The DEST and ORIG path parameters MUST be substituted as follows:

- DEST: The percent-encoded and canonicalized destination telephone number (TN) or URI representing the final called party, derived from the SIP request URI after any retargeting. If the destination is not a valid telephone number, a percent-encoded URI MAY be used (e.g., urn:service:sos encoded as urn%3Aservice%3Asos).
- ORIG: The percent-encoded and canonicalized calling party TN or URI, typically obtained from the SIP From or P-Asserted-Identity header. Canonicalization of TNs follows {{RFC8224}}, and percent encoding follows {{RFC3986}}.

PASSporTs may not be retrievable if the original call used a URI-based identity that was altered or lost during protocol transitions (e.g., SIP -> TDM -> SIP).

### Request definition

Method: GET
Path: /passports/{DEST}/{ORIG}
Headers: Authorization: Bearer \<JWT\>

#### Authorization JWT Requirements

The Authorization header MUST contain a JWT that meets the following requirements:

- The JWT MUST be signed using ES256 with a valid delegate certificate that chains to a trusted STI-CA root.
- The iss and sub claims MUST match the SPC in the TNAuthList extension of the certificate used to sign the JWT.
- The action claim MUST be set to "retrieve".
- The dest and orig claims MUST reflect the decoded values of the corresponding path parameters.

If the authentication JWT does not meet these requirements, the request MUST be rejected.

#### Example JWT access token:

Header:

~~~ json
{
  "alg": "ES256",
  "x5u": "https://certs.example.com/example.crt"
}
~~~

Payload: 

~~~ json
{
  "iat": 1608048420,
  "action": "retrieve",
  "sub": "12013776051",
  "iss": "12013776051",
  "aud": "cps.example.com",
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "dest": {
    "tn": ["19032469103"]
  },
  "orig": {
    "tn": "12013776051"
  }
}
~~~

### Response definition

Success: 200 OK
Header: Content-Type: application/json
Body:

~~~ json
{
  "tokens": [
    "eyJhbGciOiJFUzI1NiIsIn...",  // Original publish JWT(s)
    "eyJhbGciOiJFUzI1NiIsIn..."   // Optional republish JWT(s)
  ],
  "passports": [
    "eyJhbGciOiJFUzI1NiIsIn..."   // One or more PASSporT JWTs
  ]
}
~~~

Failure: status > 399

- 401 Unauthorized - if the JWT is missing or invalid
- 403 Forbidden - if certificate constraints are violated
- 404 Not Found - if no PASSporTs are available
- 429 Too Many Requests - if rate limits are exceeded
- 503 Service Unavailable - if the CPS is temporarily unable to respond

Response codes MUST follow guidance in {{RFC6585}}. If a 5xx response is received, the requester MAY attempt retrieval from an alternate CPS endpoint, subject to local policy.

### Example Request

~~~
GET /passports/19032469103/12013776051 HTTP/1.1
Content-Length: 0
Host: cps.example.com
Authorization: Bearer
eyJhbGciOiJFUzI1NiIsIng1dSI6Imh0dHBzOi8vY2VydGlmaWNhdGVzLmV4YW1wbGU
uY29tL2V4YW1wbGUuY3J0In0.eyJpYXQiOjE2MDgwNDg0NDQsImFjdGlvbiI6InJldH
JpZXZlIiwic3ViIjoiMTIzNCIsImlzcyI6IjEyMzQiLCJhdWQiOiJjcHMuZXhhbXBsZ
S5jb20iLCJqdGkiOiJiODBlMTAyMy04ZGM0LTQ2NWQtYTFhYS1mMDhlODhmODkyNjUi
LCJkZXN0Ijp7InRuIjpbIjE5MDMyNDY5MTAzIl19LCJvcmlnIjp7InRuIjoiMTIwMTM
3NzYwNTEifX0.k3S9oNyj9B8olbgaObL-eqdnCAB_sZaBOSuzfo8R7PDyqEBUOVvm-p
FzG24giW8ztlg6339TerVQRGUQNhx9HQ
~~~

### Example Response

~~~
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 958

{"passports":["eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc
3Nwb3J0IiwieDV1IjoiaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMuZXhhbXBsZS5jb20vZXhh
bXBsZS5jcnQifQ.eyJhdHRlc3QiOiJBIiwiZGVzdCI6eyJ0biI6WyIxOTAzMjQ2OTEw
MyJdfSwiaWF0IjoxNTg0OTgzNDAyLCJvcmlnIjp7InRuIjoiMTIwMTM3NzYwNTEifSw
ib3JpZ2lkIjoiNGFlYzk0ZTItNTA4Yy00YzFjLTkwN2ItMzczN2JhYzBhODBlIn0.EM
fXHyowsI5s73KqoBzJ9pzrrwGFNKBRmHcx-YZ3DjPgBe4Mvqq9N-bThN1_HTWeSvbru
Ayet26fetRL1_bn1g"]}
~~~

# Authentication Service Procedures for VESPER OOB

When participating in VESPER OOB, Authentication Services that sign PASSporTs MUST adhere to all requirements of the core VESPER specification {{I-D.wendt-stir-vesper}} and additional procedures specified herein to ensure the integrity of out-of-band transactions and compatibility with verifier expectations.

## Delegate Certificate Requirements

Delegate certificates used to sign PASSporTs in VESPER OOB MUST be issued under authority tokens that represent an explicit right-to-use a telephone number.  These certificates MUST include:
- One or more Signed Certificate Timestamps (SCTs) from certificate transparency logs as defined in {{I-D.wendt-stir-certificate-transparency}}.
- A CPS URI in the Call Placement Service (CPS) X.509 extension, enabling discovery of the associated OOB Call Placement Service (CPS) as defined in {{I-D.sliwa-stir-cert-cps-ext}}.

## PASSporT Construction Requirements

PASSporTs signed in a VESPER OOB deployment MUST meet the following conditions:

- The PASSporT MUST be signed with a delegate certificate whose authority token authorizes the use of the specific originating telephone number.
- The `orig` claim MUST contain the telephone number or URI as authorized by the delegate certificate.
- The `dest` claim MUST reflect the final destination of the call after any retargeting.
- The `iat` claim MUST represent a timestamp within an acceptable freshness window (e.g., 5 minutes).
- The JWT `x5c` header MUST contain the certificate chain including the delegate certificate and its SCT(s).

The Authentication Service MUST also publish the signed PASSporT to the CPS endpoint identified by the CPS URI in the delegate certificate.

# CPS URI and OOB CPS Discovery

CPS URIs are associated with the delegate certificates through the CPS URI extension defined in {{I-D.sliwa-stir-cert-cps-ext}}. Verifiers are expected to obtain the CPS URI for a specific telephone number via transparency-enabled discovery mechanisms described in {{I-D.sliwa-stir-oob-transparent-discovery}}. The CPS URI identifies the base URL for the Call Placement Service responsible for publishing and serving PASSporTs for calls associated with that telephone number.

The CPS URI MUST resolve to a reachable and operational CPS that supports the VESPER OOB interface defined in this document. It is assumed that the CPS implements the endpoints defined in the HTTPS interface specification, including '/health', '/passports/{DEST}/{ORIG}', and appropriate authorization mechanisms.

# Verification Service Procedures for VESPER OOB

Verification Services that retrieve and validate PASSporTs via the VESPER OOB model MUST implement the following procedures in addition to those defined fundamentally in {{RFC8224}} and specific to VESPER defined in {{I-D.wendt-stir-vesper}}.

## Retrieval and Validation Process

1. CPS URI Resolution: Retrieve the CPS URI from an appropriate CPS discovery service as discussed and defined in {{I-D.sliwa-stir-oob-transparent-discovery}} to locate the specific '/passports/{DEST}/{ORIG}' endpoint.
2. PASSporT Retrieval: Submit a 'GET' request to the CPS endpoint using a properly formed JWT in the Authorization header.
3. Authentication JWT Validation: Ensure the JWT is:
   - Signed by a valid STI certificate that chains to a trusted root.
   - Contains matching 'iss' and 'sub' values as authorized in the certificate's TNAuthList.
   - Has an 'action' claim set to '"retrieve"'.
   - Contains 'orig' and 'dest' claims matching the intended retrieval parameters.

## PASSporT Validation

Once retrieved, the verifier MUST:

- Validate the PASSporT signature using the provided certificate referenced in the 'x5c' Header.
- Verify that the delegate certificate:
  - Is valid and chains to a trusted authority.
  - Contains valid SCTs proving inclusion in a certificate transparency log.
  - Was issued under a valid, verifiable authority token (directly or via reference).
- Check that the 'iat' claim is within an acceptable range relative to the call time.
- Optionally, verify the transparency receipt (if present) that correlates the certificate and signing event.

These validation steps ensure end-to-end trust in the originating identity of the call, even across heterogeneous network paths or in the absence of SIP Identity header delivery.

# Security Considerations

TBD

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

The authors thank the contributors of the STIR working group and authors of ATIS-1000096, many of the concepts and mechanisms have been aligned and extended in this document to support the Vesper OOB Framework for PASSporT delivery signed with delegate certificates.
