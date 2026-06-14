---
title: "VESPER Out-of-Band OOB"
abbrev: "VESPER OOB"
category: std

docname: draft-wendt-stir-vesper-oob-03
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Applications and Real-Time"
workgroup: "Secure Telephone Identity Revisited"
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
    country: US
 -
    fullname: Rob &#x015A;liwa
    organization: Somos Inc.
    email: robjsliwa@gmail.com
    country: US

normative:
  RFC3261:
  RFC8224:
  RFC8225:
  RFC8226:
  RFC8816:
  RFC9060:
  RFC9447:
  I-D.ietf-stir-certificate-transparency:
  I-D.wendt-stir-vesper:
  I-D.wendt-stir-tn-domain-binding:
  I-D.sliwa-stir-cert-cps-ext:
  I-D.ietf-stir-rfc4916-update:

informative:
  ATIS-1000105:
    title: "ATIS-1000105 - Signature-based Handling of Asserted information using Tokens (SHAKEN): Out-of-Band PASSporT Transmission Between Service Providers that Interconnect using TDM"
    author:
      - org: ATIS
    target: https://access.atis.org/higherlogic/ws/public/download/79509/ATIS-1000105.pdf

--- abstract

This document describes a mechanism for delivering authenticated telephone call identity information using the VESPER framework for use where in-band signaling does not carry the identity end to end, or where there is no in-band path between the parties at all. By supporting an out-of-band (OOB) transport model, this approach enables entities to publish and retrieve signed PASSporT assertions independent of end-to-end delivery within an in-band signaling path such as a SIP-based VoIP network. These PASSporTs are signed with VESPER delegate certificates, which are bound certificates that co-validate the subject's telephone number right-to-use and a domain identifier, and which are recorded in certificate transparency logs so that the authorization is publicly auditable and cryptographically provable. This document also introduces support for Connected Identity to the STIR OOB model, enabling the called party to respond with a signed PASSporT asserting its identity, thereby binding the identities of both parties to the transaction and enhancing end-to-end accountability. The OOB mechanism provides a delivery path for PASSporTs where in-band delivery within a signaling path such as SIP is unavailable or is not the path used, enabling verifiers to confirm the association between the originating telephone number and the identity asserting authority as part of the broader VESPER trust framework.

--- middle

# Introduction

The STIR framework enables the signing and verification of telephone communications using PASSporT {{RFC8225}} objects carried in SIP {{RFC3261}} in Identity Header Fields defined in {{RFC8224}}. However, there are scenarios where SIP-based in-band transmission is not feasible or the Identity Header Field may not be supported, such as legacy TDM interconnects or where intermediary network elements strip SIP Identity headers. STIR Out-of-Band (OOB) {{RFC8816}} addresses this generally for STIR by defining an OOB delivery model.

The VESPER framework {{I-D.wendt-stir-vesper}} composes existing STIR mechanisms, delegate certificates, authority tokens, and certificate transparency, into a trust framework. A VESPER delegate certificate is telephone number scoped and is a bound certificate as defined in {{I-D.wendt-stir-tn-domain-binding}}, in which the subject's telephone number right-to-use and a domain identifier are co-validated at issuance and recorded in certificate transparency logs. As described in {{I-D.wendt-stir-vesper}}, the delegate certificate is delegated from a parent certificate held by an authority that is authoritative in the telephone network, strengthening the association between telephone number assignments and the entities authorized to use them in signed PASSporTs.

This document describes how the VESPER framework is applied to an out-of-band delivery mechanism corresponding to the model described in {{RFC8816}}. It enables authorized delegate certificate holders to deliver PASSporTs over an out-of-band path for retrieval and validation by a STIR Verification Service, maintaining continuity of trust across heterogeneous networks.

The VESPER OOB delivery model is based on a publish-and-retrieve interface using an open discovery model for PASSporT Placement Services (PPS). This document describes the publish-and-retrieve mechanism and its required properties, building on the concepts in {{RFC8816}}, rather than prescribing a specific interface. It utilizes the following:

- A mechanism for announcing the associated OOB PASSporT Placement Services (PPSs) using the PPS URI extension defined in {{I-D.sliwa-stir-cert-cps-ext}}.
- A discovery mechanism for OOB endpoints using STI certificate transparency log monitoring, where PPS URIs embedded in delegate certificates become publicly discoverable when those certificates are logged.

It also optionally supports Connected Identity {{I-D.ietf-stir-rfc4916-update}}, enabling both parties to authenticate their telephone numbers and establish end-to-end identity assurance, as also adopted by VESPER {{I-D.wendt-stir-vesper}}.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

VESPER: Verifiable STI Presentation and Evidence for RTU {{I-D.wendt-stir-vesper}}.

PASSporT: Personal Assertion Token as defined in {{RFC8225}}.

Delegate Certificate: A certificate issued to an entity asserting right-to-use for a telephone number, based on an authority token, as defined in {{RFC9060}} and profiled in {{I-D.wendt-stir-vesper}}.

Bound Certificate: A STIR certificate in which a domain identifier in the SubjectAltName and the TNAuthList authority are co-validated at issuance, as defined in {{I-D.wendt-stir-tn-domain-binding}}. A VESPER delegate certificate is a bound certificate whose TNAuthList authority is the subject's telephone number right-to-use.

Authority Token: A signed assertion that authorizes the issuance of a delegate certificate and represents the authorization of a subject's right-to-use a telephone number and any associated claims, defined in {{RFC9447}}.

PASSporT Placement Service (PPS): The service that stores signed PASSporTs published by an originating party and serves them to an authorized retrieving party, and that supports the optional Connected Identity response exchange. Earlier STIR out-of-band work, including {{RFC8816}} and {{ATIS-1000105}}, refers to this role as a Call Placement Service (CPS). This document uses PASSporT Placement Service for two reasons. First, the CPS acronym collides with Certification Practice Statement (CPS) as used in {{RFC8226}} and certificate policy practice generally, which is a recurring source of ambiguity in a document that deals with both certificates and this service. Second, the service places and serves PASSporTs and is not limited to telephone calls; the same mechanism is intended to apply to applications beyond telephone calls, for which a PASSporT-centric name is more accurate.

PPS URI: PASSporT Placement Service (PPS) URI extension in X.509 certs {{I-D.sliwa-stir-cert-cps-ext}}. The PPS URI identifies the PASSporT Placement Service (PPS) for the telephone numbers covered by the certificate.

PPS Discovery: The process of identifying the PPS endpoint responsible for a given telephone number by monitoring STI-CT logs for delegate certificates containing the PPS URI extension defined in {{I-D.sliwa-stir-cert-cps-ext}}.

# VESPER OOB Architectural Overview

The VESPER OOB architecture enables the out-of-band signing, publishing, discovery, and verification of PASSporTs using a trust framework based on delegate certificates and transparency mechanisms. The out-of-band path is a general mechanism for delivering PASSporTs from an originating party to a destination party, independent of any particular signaling protocol. It may operate alongside an in-band signaling path, such as a SIP call in which the PASSporT would otherwise travel in an Identity header field, or it may be the sole channel between the two parties, as in messaging, non-SIP signaling, or other applications where there is no in-band path to carry the PASSporT. Figure 1 illustrates the flow of identity data between the authentication service, the out-of-band PASSporT Placement Service (PPS), and the verification service, with the in-band signaling path shown as an optional parallel path.

~~~
        +--------------------+  Originate communication over an
        |   Authentication   |  in-band signaling path, if any
        |     Service        |  (e.g. SIP INVITE with RFC8224
        | (Originating Party)|   Identity Header Field)
        +---------+----------+-------------------+
                  |                              |
                  | 1. Publish PASSporT with     |
                  |    Delegate Certificate      |
                  v                          .~~~~~~~~~~.
        +---------+----------+           .-''             '-.
        |        PPS         |        ,.'    In-band         '.
        |                    |       /    signaling path     |
        +---------+----------+      |    (e.g. SIP), if any  /
                  ^                  '.___..~~~~~~..______.'
                  |                              |
                  | 2. Retrieve PASSporT         |
                  |                              |
        +---------+----------+                   |
        |    Verification    |                   |
        |      Service       |<------------------+
        | (Destination Party)|  Receive communication over the
        +--------------------+  in-band signaling path, if any
~~~
Figure 1 - Architecture showing out-of-band PASSporT delivery alongside an optional in-band signaling path

# VESPER OOB Mechanism

This section describes how PASSporTs are delivered out of band through a PASSporT Placement Service (PPS), and how Connected Identity allows the called party to return a signed response. Following the approach of {{RFC8816}}, this document describes the mechanism and the properties an implementation must preserve, rather than prescribing a specific API. A PPS interface that provides these operations and preserves these properties is conformant; implementers may adopt an existing publish-and-retrieve interface such as the one described in {{ATIS-1000105}}, or define their own.

## Operations

The mechanism is built from three operations against a PPS:

- Publish: the originating party places one or more signed PASSporTs for a given originating and destination pair into the PPS, so they can be retrieved by the destination party. A publish operation MAY also request a Connected Identity exchange, in which case the PPS returns a transaction handle that identifies the exchange.
- Retrieve: the destination party obtains the PASSporTs published for a given originating and destination pair, and, where a Connected Identity exchange was requested, learns the transaction handle.
- Respond: where Connected Identity is in use, the destination party places a signed response PASSporT against the transaction handle, which the originating party then retrieves.

Each operation is authorized by the requesting party signing its request with its VESPER delegate certificate, so that the PPS and the counterparty can confirm the requester is authorized for the telephone number involved. The integrity of the published PASSporTs is bound to that authorization so that stored content cannot be substituted. The mechanism used to convey and authorize these operations is not defined here; an implementation may use the signed-request mechanism of {{ATIS-1000105}} or an equivalent.

## Required Properties

An implementation of the VESPER OOB mechanism preserves the following properties, however the PPS interface is realized. Some of these properties are guaranteed cryptographically by the signed request and the signed PASSporT, while others are enforced by the PPS as a relied-upon party; the Security Considerations section discusses this distinction and its consequences.

- Authorization: publish, retrieve, and respond requests are authorized by the requesting party using its VESPER delegate certificate. The PPS and the counterparty can verify that the requester is authorized for the originating or destination identifier it is acting for, consistent with the certificate's TNAuthList.
- Scoping: retrieval is scoped to a specific originating and destination pair, so that a party can obtain only the PASSporTs intended for an exchange it is part of.
- Integrity: the authorization of a publish or respond request is bound to the PASSporT content it carries, so that the stored PASSporTs cannot be altered or substituted without detection.
- Replay resistance: requests are protected against replay, for example through a unique request identifier and a freshness window, and are scoped to a single transaction rather than reused.
- Confidentiality of the exchange: in a Connected Identity exchange, the transaction handle and the response are disclosed only to the parties of the original transaction. In particular, the response is made available only to the party that performed the original publish.
- Transport security: all PPS interactions occur over a server-authenticated secure transport.

## Mechanism Flow

The following sequence illustrates the mechanism. Steps 1 and 2 are the basic publish-and-retrieve flow for delivering a PASSporT from the originating party (A) to the destination party (B). Steps 3 and 4 are the optional Connected Identity exchange, in which B returns a signed response PASSporT for A to retrieve.

~~~
   A (Originating)              PPS               B (Destination)
        |                         |                       |
        | 1. Publish PASSporT(s)  |                       |
        |    for (orig=A,dest=B), |                       |
        |    authorized by A's    |                       |
        |    delegate certificate |                       |
        | ----------------------> |                       |
        |   (handle, if Connected |                       |
        |     Identity requested) |                       |
        | <---------------------- |                       |
        |                         |  2. Retrieve PASSporT(s)
        |                         |     for (orig=A,dest=B),
        |                         |     authorized by B's
        |                         |     delegate certificate
        |                         | <-------------------- |
        |                         |  PASSporT(s) (+ handle
        |                         |  if Connected Identity)
        |                         | --------------------> |
        |                         |                       |
        |                         |  3. Respond with rsp  |
        |                         |     PASSporT against  |
        |                         |     handle, authorized
        |                         |     by B's delegate cert
        |                         | <-------------------- |
        | 4. Retrieve rsp         |                       |
        |    PASSporT for handle, |                       |
        |    authorized by A's    |                       |
        |    delegate certificate |                       |
        | ----------------------> |                       |
        | <---------------------- |                       |
        |    rsp PASSporT         |                       |
        |                         |                       |
~~~
Figure 2 - VESPER OOB publish/retrieve (steps 1-2) and optional Connected Identity exchange (steps 3-4)

In the basic flow, A publishes the PASSporTs it would otherwise have carried in the SIP Identity header field, and B retrieves and verifies them as part of terminating the call. In the Connected Identity flow, the transaction handle returned at publish ties B's response to the original transaction. B can respond only after retrieving the original PASSporTs, so that it has had the opportunity to verify A before asserting its own identity, and only A, as the original publisher, can retrieve B's response. The verification of the retrieved PASSporTs, in both directions, is described in the verification procedures below.

# Authentication Service Procedures for VESPER OOB

Authentication Services that sign PASSporTs for out-of-band delivery follow the core VESPER specification {{I-D.wendt-stir-vesper}}, together with the additional procedures in this section that are specific to the out-of-band case.

The role of the Authentication Service is to author the PASSporT: to construct and sign it using the VESPER delegate certificate and the VESPER PASSporT usage profile, asserting the originating identity. This authored PASSporT is the same artifact regardless of how it is delivered. In the in-band case it travels with the communication, for example in a SIP Identity header field; in the out-of-band case it is the PASSporT placed in the PASSporT Placement Service (PPS) for the destination party to retrieve. Out-of-band delivery may be the sole path between the two parties, as in messaging or other applications where there is no in-band path that can carry the PASSporT, or it may run alongside an in-band copy of the same PASSporT. In all of these cases the authoring of the PASSporT is unchanged; what is specific to out-of-band operation is that the authored PASSporT is published to a PPS rather than, or in addition to, being carried in band. The subsections below state the certificate properties this relies on and the delivery step that is specific to out-of-band operation.

## Delegate Certificate Requirements

Delegate certificates used to sign PASSporTs in VESPER OOB are bound certificates issued in accordance with {{I-D.wendt-stir-tn-domain-binding}}, which co-validates the domain identifier and the subject's telephone number right-to-use in the TNAuthList at issuance, as profiled by VESPER in {{I-D.wendt-stir-vesper}}. These certificates MUST include:

- One or more Signed Certificate Timestamps (SCTs) from certificate transparency logs as defined in {{I-D.ietf-stir-certificate-transparency}}.
- A PPS URI in the PASSporT Placement Service (PPS) X.509 extension, enabling discovery of the associated OOB PASSporT Placement Service (PPS) as defined in {{I-D.sliwa-stir-cert-cps-ext}}.

## PASSporT Construction Requirements

PASSporTs delivered over VESPER OOB are constructed and signed as defined in the VESPER PASSporT usage profile {{I-D.wendt-stir-vesper}}, which applies the procedures of {{RFC8224}} and {{RFC8225}} and the bound certificate rules of {{I-D.wendt-stir-tn-domain-binding}}. VESPER OOB adds no requirements on the content of the PASSporT itself; the `orig`, `dest`, and `iat` claims and the `x5c` and `x5u` headers are populated as that profile specifies.

The one requirement specific to OOB is delivery: rather than, or in addition to, carrying the PASSporT in a SIP Identity header field, the Authentication Service publishes the signed PASSporT to the PPS identified by the PPS URI in the signing certificate, using the publish operation of the VESPER OOB mechanism.

# PPS URI and OOB PPS Discovery

PPS URIs are associated with VESPER delegate certificates through the PPS URI extension defined in {{I-D.sliwa-stir-cert-cps-ext}}. This extension embeds an HTTPS URI identifying the PPS endpoint responsible for publishing and serving PASSporTs for the telephone numbers covered by the certificate's TNAuthList.

When a VESPER delegate certificate containing a PPS URI extension is submitted to a STI-CT log, the PPS URI becomes publicly visible and verifiable. Parties that wish to discover the PPS for a given telephone number do so by monitoring STI-CT logs for delegate certificates that include a PPS URI extension, extracting the telephone numbers and PPS URI from each certificate, and associating the covered telephone numbers with the indicated PPS endpoint. This approach provides a transparent, cryptographically verifiable discovery mechanism that does not require bilateral provisioning or static configuration between service providers.

The discovery process follows these steps:

1. A VESPER delegate certificate containing a TNAuthList and PPS URI extension is issued and submitted to a STI-CT log, generating an SCT.
2. A monitoring party observes the log, verifies the certificate chain to a trusted STI root, validates the SCT, and extracts the telephone-number-to-PPS mappings.
3. Authentication Services and Verification Services consult these mappings to identify the appropriate PPS endpoint for a given call.
4. PASSporTs are published or retrieved using the discovered PPS URI as part of the OOB authentication process.

Implementations MAY maintain local caches of telephone-number-to-PPS mappings, respecting certificate validity periods when using extracted data. PPS operators SHOULD publish delegate certificates in multiple STI-CT logs to ensure broad visibility. The PPS URI MUST resolve to a reachable and operational PPS that supports the VESPER OOB mechanism defined in this document.

The mechanism permits a certificate to carry more than one PPS URI, so that an operator can advertise multiple PPS instances, including regional or edge instances. Where multiple instances are advertised, an implementation can select among them or fail over between them using local policy such as lowest latency or geographic proximity. The degree of redundancy that is appropriate is a matter of deployment experience and local policy, and is not specified here.

# Verification Service Procedures for VESPER OOB

Verification Services that retrieve and validate PASSporTs via the VESPER OOB model MUST implement the following procedures in addition to those defined fundamentally in {{RFC8224}} and specific to VESPER defined in {{I-D.wendt-stir-vesper}}.

## Retrieval and Validation Process

- PPS URI Resolution: Determine the PPS URI for the given telephone number by consulting telephone-number-to-PPS mappings derived from monitoring STI-CT logs for delegate certificates containing the PPS URI extension, as described in the PPS URI and OOB PPS Discovery section of this document.
- PASSporT Retrieval: Perform the retrieve operation of the VESPER OOB mechanism against the resolved PPS, scoped to the originating and destination pair and authorized by the verifier's VESPER delegate certificate, as described in the VESPER OOB Mechanism section.
- Multiple PASSporT Handling: If the retrieved response contains multiple PASSporTs, the verifier MUST validate each PASSporT independently. All PASSporTs MUST share the same `orig`, `dest`, and `iat` values and MUST be signed by the same delegate certificate. If any PASSporT fails validation, the verifier SHOULD reject the entire set and SHOULD log the failure for diagnostic purposes. The verifier MAY apply local policy to determine which PASSporT types are actionable.

## PASSporT Validation

Once retrieved, the verifier MUST validate the PASSporT and its signing certificate according to {{RFC8224}}, the VESPER framework {{I-D.wendt-stir-vesper}}, and the bound certificate verification rule defined in {{I-D.wendt-stir-tn-domain-binding}}. In the OOB context this includes the following:

- Validate the PASSporT signature using the certificate chain in the 'x5c' header.
- Apply the bound certificate verification rule of {{I-D.wendt-stir-tn-domain-binding}}, confirming that the domain in the 'x5u' URL matches the dNSName SubjectAltName of the signing certificate and treating the domain identifier as the identity of the authority holder only as bound to the TNAuthList.
- Verify that the delegate certificate:
  - Is valid and chains to a trusted authority.
  - Contains valid SCTs proving inclusion in a certificate transparency log as defined in {{I-D.ietf-stir-certificate-transparency}}.
  - Was issued under a valid, verifiable authority token.
- Check that the 'iat' claim is within an acceptable range relative to the call time.

These validation steps ensure end-to-end trust in the originating identity of the call, even across heterogeneous network paths or in the absence of SIP Identity header delivery.

## Connected Identity Validation

When a Connected Identity response PASSporT (`rsp`) is retrieved by the Verification Service (VS), it MUST be validated in accordance with the procedures defined in {{I-D.ietf-stir-rfc4916-update}} and the VESPER framework {{I-D.wendt-stir-vesper}}.

Specifically:

The `rsp` PASSporT MUST be signed using a valid VESPER delegate certificate associated with the `dest` telephone number of the original call.

The certificate used to sign the `rsp` PASSporT MUST:

- Be issued under a valid authority token authorizing use of the `dest` number.
- Contain TNAuthList values that include the `dest` identifier.
- Include valid Signed Certificate Timestamps (SCTs) from a Certificate Transparency log.

The VS MUST validate the PASSporT signature and the delegate certificate's trust chain, including SCT verification and certificate expiration status.

The VS MUST confirm that the `orig` and `dest` claims in the `rsp` PASSporT match those of the original call. That is:

- The `orig` claim in the `rsp` PASSporT MUST match the `orig` claim of the original PASSporT.
- The `dest` claim in the `rsp` PASSporT MUST match the `dest` claim of the original PASSporT.

The key distinction from typical STIR verification is that the entity signing the `rsp` PASSporT is asserting control over the `dest` number, and the delegate certificate used in the signature MUST be valid for that number.

The `iat` claim in the `rsp` PASSporT MUST be within an acceptable freshness interval as defined by local policy.

If these validations succeed, the verifier can confirm that the called party has cryptographically asserted its identity using a VESPER-authorized certificate, completing the Connected Identity flow. Any failure in these validations MUST cause the `rsp` PASSporT to be rejected.

# Security Considerations

PASSporTs in VESPER OOB are signed using delegate certificates issued under the certificate policy defined in {{RFC8226}} and containing valid SCTs as defined in {{I-D.ietf-stir-certificate-transparency}}, and verifiers validate the certificate trust chain and SCT inclusion as specified in the Verification Service Procedures section. This dependence on the delegate certificate and its transparency evidence is what allows a verifier to establish the originating identity independently of how the PASSporT was delivered.

The publish, retrieve, and respond operations are authorized as described in the VESPER OOB Mechanism section, with each request signed by the requesting party's VESPER delegate certificate, scoped to a single transaction, and protected against replay through a unique request identifier and a short freshness window. Because the integrity of a published PASSporT is bound to that authorization, stored content cannot be substituted without detection.

A PPS is not assumed to be an openly writable, anonymously accessible endpoint. PPS operators are expected to administer their own admission controls governing which parties may reach the service at all, for example through operator-managed credentials, peering arrangements, or network-level access policy. The design of that admission layer is a matter for the operator and is out of scope for this document. Within an admitted context, the requirement that each operation be signed by the requesting party's VESPER delegate certificate is what authorizes the specific action on a specific telephone number. This is an appropriate use of the delegate certificate: the certificate is the cryptographic representation of the subject's right-to-use for the telephone numbers in its TNAuthList, so a request signed by it, and scoped to those numbers, expresses exactly the authorization needed to publish or retrieve PASSporTs for them. A party cannot use this mechanism to publish for a telephone number it does not hold a valid certificate for.

The authentication of the requester and the integrity of each PASSporT are cryptographic and do not depend on the PPS behaving honestly: a verifier validates each retrieved PASSporT and its signing certificate independently, so a misbehaving or compromised PPS cannot cause acceptance of a forged or altered identity assertion. Other properties, such as scoping retrieval to the intended originating and destination pair and keeping a Connected Identity exchange confidential to its two parties, are enforced by the PPS as a relied-upon party rather than guaranteed cryptographically by the signed request alone. A compromised PPS could therefore affect the availability of PASSporTs, or the confidentiality and scoping of an exchange, even though it cannot forge the identities asserted within. The degree of additional assurance an operator places on PPS behavior is a matter of deployment and local policy.

In a Connected Identity exchange, the transaction handle and the response are sensitive. The Confidentiality property required in the VESPER OOB Mechanism section limits their disclosure to the parties of the original transaction, with the response made available only to the party that performed the original publish. A further concern is that the existence or pending state of a transaction handle can itself be sensitive: to avoid confirming a handle to an unauthorized requester, a PPS should not distinguish, in its observable behavior, between a handle that does not exist and one the requester is not authorized to access.

A PPS handles identity data and is exposed to request-volume abuse, so operators should apply rate limiting and should retain identity data only as long as operationally necessary.

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

The authors thank the contributors of the STIR working group and the authors of ATIS-1000105, whose out-of-band publish-and-retrieve mechanism informed the mechanism described in this document for PASSporT delivery signed with VESPER delegate certificates.
