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
  title: "Technical Report on SHAKEN Out-of-Band PASSporT Transmission Involving TDM-SIP Interworking"
  author: 
    - org: ATIS
  target: https://access.atis.org/apps/group_public/download.php/52450/ATIS-1000096.pdf
  seriesinfo:
    ATIS: ATIS-1000096

--- abstract

This document describes a mechanism for delivering authenticated telephone call identity information using the VESPER framework in environments where SIP signaling is unavailable or unsuitable. By supporting an out-of-band (OOB) transport model, this approach enables entities to publish and retrieve signed PASSporT assertions independent of SIP networks. These PASSporTs are signed with delegate certificates that were authorized for issuance by corresponding authority tokens, which represent the trust and validation of telephone number control and related claim information. Transparency features ensure that these authorizations are publicly auditable and cryptographically provable, supporting a higher standard of trust. The OOB mechanism serves as an alternative delivery path for PASSporTs in cases where end-to-end in-band SIP delivery is not possible, enabling verifiers to confirm the association between the originating telephone number and the identity asserting authority as part of the broader VESPER trust framework.

--- middle

# Introduction

The STIR framework enables the signing and verification of telephone calls using PASSporT objects carried in SIP. However, there are scenarios where SIP-based in-band transmission is not feasible, such as legacy TDM interconnects or where intermediary network elements strip SIP Identity headers. {{RFC8816}} addresses this by defining an Out-of-Band (OOB) delivery model.

The VESPER framework {{I-D.wendt-stir-vesper}} extends the STIR framework by introducing support for vetted delegate certificates using authority tokens and certificate transparency logs and monitoring to enhance reliability and trust of certificates and the associated claims authorized to be made by the use of those certificates for signed PASSporTs. The use cases motivating these enhancements are outlined in {{I-D.wendt-stir-vesper-use-cases}}.

This document describes how to expand the Vesper framework to use an OOB delivery mechanism corresponding to that described by {{RFC8816}}. These delegate certificates are issued based on authority tokens that attest to the vetting and authorization of the entity to use the number and make identity assertions. Thus enabling authorized delegate certificate holders that sign calls via a STIR Authtentication Service a non-SIP-based path to deliver PASSporTs containing authorized verifiable claims, leveraging the Vesper trust model, to a STIR Verification Service that wants to validate the originating telephone number and associated claims in a similar manner to SIP-based STIR defined in {{RFC8224}}.

OOB delivery is critical in extending the utility of STIR to networks where SIP identity headers cannot be delivered end-to-end. It provides a verifiable alternative path for transmitting PASSporTs and proving the originating telephone number's association to the signing identity.

This document defines:

A REST-based interface for publishing and retrieving VESPER PASSporTs.

A mechanism for discovering delegate certificate services using the CPS URI extension defined in {{I-D.sliwa-stir-cert-cps-ext}}.

A discovery mechanism for OOB endpoints based on {{I-D.sliwa-stir-oob-transparent-discovery}}.

The requirement to include certificate transparency receipts with delegate certificates.

The delivery model assumes a one-way publish-and-retrieve interface.

NOTE confirm this: omitting re-publish, revocation, or update mechanisms.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

VESPER: Verifiable Entity STIR Passport Entity Representation {{I-D.wendt-stir-vesper}}.

PASSporT: Personal Assertion Token as defined in {{RFC8225}}.

Delegate Certificate: A certificate issued to an enterprise or user entity asserting right-to-use for a telephone number, based on an authority token, defined in {{RFC9060}}.

Authority Token: A signed assertion that authorizes the issuance of a delegate certificate and represents the vetting of a subject's control over a telephone number and any associated claims defined in {{RFC9447}}.

CPS URI: Call Placement Service (CPS) URI extension in X.509 certs for OOB CPS service discovery.

# Vesper OOB Architectural Overview

The VESPER-OOB model introduces an interface between:

- Authentication Service: Entity signing Vesper PASSporTs with a delegate certificate that was issued based on valid authority tokens.
- OOB CPS: RESTful service endpoint where signed PASSporTs are published and made available.
- Verification Service: Retrieves PASSporTs, validates the signature, checks the certificate transparency inclusion, and confirms trust via the authority token and CPS discovery.

~~~~~~~~~~~~~
        +--------------------+  Send SIP INVITE /w Identity
        |   Authentication   |  Header Field (RFC8824/VESPER)
        |     Service        |-------------------+
        |  (Calling Party)   |                   |
        +---------+----------+                   |
                  |                              |
                  | 1. Publish PASSporT with     |
                  |    Delegate Certificate      |
                  v                          .~~~~~~~~~~.
        +---------+----------+           .-''             '-.
        |        CPS         |        ,.'   SIP-based VoIP  '.
        |    (REST/HTTPS)    |       /        Routing        |      
        +---------+----------+      |         Network       /
                  ^                  '.___..~~~~~~..______.'
                  |                              |
                  | 2. Retrieve PASSporT         |
                  |                              |
        +---------+----------+                   |
        |    Verification    |                   |
        |      Service       |<------------------+
        |   (Called Party)   |  Receive SIP INVITE /w Identity
        +--------------------+  Header Field (RFC8824/VESPER)
~~~~~~~~~~~~~~

Figure 1 - Architecture showing both in-band and out-of-band PASSporT delivery

# REST Interface Specification

The interface design is conceptually aligned with the interface model described in ATIS-1000096 Section 5 [ATIS-1000096], and supports:

- POST /passport to publish a signed PASSporT.
- GET /passport/{tn}/{orig-date} to retrieve the PASSporT based on telephone number and orig-date.
- Optional GET /health endpoint for service monitoring.

All endpoints MUST be served over HTTPS. The POST endpoint MUST require authentication. The GET endpoint SHOULD be unauthenticated, but MUST be rate-limited and optionally support authorization policies for access control.

# Discovery via CPS URI

Delegate certificates MUST include a CPS URI in the Certificate Practice Statement X.509 extension as defined in {{I-D.sliwa-stir-cert-cps-ext}}. This URI MUST resolve to a service document or OpenAPI description that advertises the OOB interface endpoint and its capabilities.

# OOB Service Discovery

As specified in {{I-D.sliwa-stir-oob-transparent-discovery}}, service discovery for VESPER OOB delivery is based on retrieving a metadata object from the CPS URI which describes the OOB endpoints and associated capabilities, such as:

- Supported PASSporT formats
- Retrieval policies (e.g., caching, retention window)
- Transparency log verification support

# Certificate Transparency and VESPER Binding

Delegate certificates MUST include one or more Signed Certificate Timestamps (SCTs) from trusted certificate transparency logs as defined in {{I-D.wendt-stir-certificate-transparency}}. VESPER transparency receipts MAY also be attached to PASSporTs or referenced externally.

Verifiers MUST validate:

- The delegate certificate is valid, within date bounds, and chains to a trusted root.
- The certificate includes transparency proofs.
- The CPS URI is accessible and matches the delegate's identity.
- The certificate was authorized for issuance by a valid authority token.

# PASSporT Requirements

- PASSporTs MUST be signed with the delegate certificate corresponding to the originating telephone number.
- The dest claim MUST match the called number.
- The iat (issued-at) claim MUST be within a valid time window.
- The JWT x5u header MUST point to the full certificate chain over HTTPS.

# Security Considerations

- All REST interfaces MUST be served over HTTPS.
- The POST interface MUST be authenticated.
- Rate-limiting MUST be enforced on unauthenticated GET endpoints.
- CT logs MUST be publicly auditable and trusted.
- CPS URI discovery MUST follow validation procedures.
- Authority tokens MUST be cryptographically verifiable and traceable to trusted vetting services.

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

The authors thank the contributors of the STIR working group and authors of ATIS-1000096, many of the concepts and mechanisms have been aligned and extended in this document to support the Vesper Framework for delegate certificates.
