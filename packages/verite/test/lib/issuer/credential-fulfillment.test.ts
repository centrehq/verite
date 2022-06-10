import { randomBytes } from "crypto"

import {
  buildCredentialApplication,
  decodeCredentialApplication
} from "../../../lib/issuer/credential-application"
import {
  buildAndSignFulfillment,
  buildAndSignVerifiableCredential
} from "../../../lib/issuer/credential-fulfillment"
import { buildKycAmlManifest } from "../../../lib/issuer/credential-manifest"
import {
  buildIssuer,
  decodeVerifiableCredential,
  decodeVerifiablePresentation,
  randomDidKey
} from "../../../lib/utils"
import { RevocationList2021Status } from "../../../types"
import { kycAmlAttestationFixture } from "../../fixtures/attestations"

describe("buildAndSignVerifiableCredential", () => {
  it("builds a valid credential application", async () => {
    // Map Issuer DID to Issuer for signing
    const issuerDid = randomDidKey(randomBytes)
    const issuer = buildIssuer(issuerDid.subject, issuerDid.privateKey)

    // Subject DID
    const subjectDid = randomDidKey(randomBytes)

    // Claims
    const attestation = kycAmlAttestationFixture

    // Builds a signed Verifiable Credential
    const vc = await buildAndSignVerifiableCredential(
      issuer,
      subjectDid,
      attestation,
      // issuanceDate defaults to now, but for testing we will stub it out
      // Note that the did-jwt-vc library will strip out any milliseconds as
      // the JWT exp and iat properties must be in seconds.
      { issuanceDate: "2021-10-26T16:17:13.000Z" }
    )

    const decoded = await decodeVerifiableCredential(vc)

    expect(decoded).toMatchObject({
      credentialSubject: {
        KYCAMLAttestation: {
          type: "KYCAMLAttestation",
          process:
            "https://demos.verite.id/schemas/definitions/1.0.0/kycaml/usa",
          approvalDate: attestation.approvalDate
        },
        id: subjectDid.subject
      },
      issuer: { id: issuerDid.subject },
      type: ["VerifiableCredential", "KYCAMLAttestation"],
      issuanceDate: "2021-10-26T16:17:13.000Z",
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        { "@vocab": "https://verite.id/identity/" }
      ]
    })
  })

  it("can optionally support a credentialStatus", async () => {
    // Map Issuer DID to Issuer for signing
    const issuerDid = randomDidKey(randomBytes)
    const issuer = buildIssuer(issuerDid.subject, issuerDid.privateKey)

    // Subject DID
    const subjectDid = randomDidKey(randomBytes)

    // Claims
    const attestation = kycAmlAttestationFixture

    // Builds a signed Verifiable Credential with a credentialStatus
    const credentialStatus: RevocationList2021Status = {
      id: "https://dmv.example.gov/credentials/status/3#94567",
      type: "RevocationList2021Status",
      statusListIndex: "94567",
      statusListCredential: "https://example.com/credentials/status/3"
    }
    const vc = await buildAndSignVerifiableCredential(
      issuer,
      subjectDid,
      attestation,
      { credentialStatus }
    )

    const decoded = await decodeVerifiableCredential(vc)

    expect(decoded.credentialStatus).toEqual({
      id: "https://dmv.example.gov/credentials/status/3#94567",
      type: "RevocationList2021Status",
      statusListIndex: "94567",
      statusListCredential: "https://example.com/credentials/status/3"
    })
  })
})

describe("buildAndSignFulfillment", () => {
  it("works", async () => {
    // We need an Issuer, Credential Application, the credential claims or attestations
    // Map Issuer DID to Issuer for signing
    const issuerDid = randomDidKey(randomBytes)
    const issuer = buildIssuer(issuerDid.subject, issuerDid.privateKey)

    const credentialIssuer = { id: issuer.did, name: "Verite" }
    const manifest = buildKycAmlManifest(credentialIssuer)

    const subjectDid = randomDidKey(randomBytes)
    const options = {}
    const encodedApplication = await buildCredentialApplication(
      subjectDid,
      manifest,
      options
    )
    const application = await decodeCredentialApplication(encodedApplication)

    const attestation = kycAmlAttestationFixture
    const encodedFulfillment = await buildAndSignFulfillment(
      issuer,
      application.holder,
      application.credential_application.manifest_id,
      application.presentation_submission,
      attestation
    )

    // The client can then decode the presentation
    const fulfillment = await decodeVerifiablePresentation(encodedFulfillment)

    // The fulfillment looks like this:
    expect(fulfillment).toMatchObject({
      vp: {
        holder: issuer.did
      },
      sub: issuer.did,
      credential_fulfillment: {
        // id: "5f22f1ea-0441-4041-916b-2504a2a4075c",
        manifest_id: "KYCAMLAttestation",
        descriptor_map: [
          {
            id: "proofOfIdentifierControlVP",
            format: "jwt_vc",
            path: "$.presentation.credential[0]"
          }
        ]
      },
      verifiableCredential: [
        {
          credentialSubject: {
            KYCAMLAttestation: {
              type: "KYCAMLAttestation",
              process:
                "https://demos.verite.id/schemas/definitions/1.0.0/kycaml/usa"
              // approvalDate: "2021-11-12T18:56:16.508Z",
            },
            id: subjectDid.subject
          },
          issuer: {
            id: issuer.did
          },
          type: ["VerifiableCredential", "KYCAMLAttestation"],
          "@context": [
            "https://www.w3.org/2018/credentials/v1",
            { "@vocab": "https://verite.id/identity/" }
          ],
          // issuanceDate: "2021-11-12T18:56:17.000Z",
          proof: {
            type: "JwtProof2020"
            // jwt: "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vdmVyaXR5LmlkL2lkZW50aXR5Il0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJLWUNBTUxBdHRlc3RhdGlvbiJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJLWUNBTUxBdHRlc3RhdGlvbiI6eyJAdHlwZSI6IktZQ0FNTEF0dGVzdGF0aW9uIiwiYXV0aG9yaXR5SWQiOiJkaWQ6d2ViOnZlcml0eS5pZCIsImFwcHJvdmFsRGF0ZSI6IjIwMjEtMTEtMTJUMTg6NTY6MTYuNTA4WiIsImF1dGhvcml0eU5hbWUiOiJWZXJpdHkiLCJhdXRob3JpdHlVcmwiOiJodHRwczovL3Zlcml0eS5pZCIsImF1dGhvcml0eUNhbGxiYWNrVXJsIjoiaHR0cHM6Ly9pZGVudGl0eS52ZXJpdHkuaWQifX19LCJzdWIiOiJkaWQ6a2V5Ono2TWtyMTJyWkx6VXNONmJxRjhqR0JYQlZtOGtLMzdxTWphRGpYa1NtUFoxcE1jYyIsIm5iZiI6MTYzNjc0MzM3NywiaXNzIjoiZGlkOmtleTp6Nk1rbTFyWFNMWFRxazFUNzRhZmZUVFNTRGU5S1RzVUdDYnFqcmpVaUVydVZQN1cifQ.7wwiJMxFB_wmB6drZlTLLE90rE_OV5CE_o48LkDVIt7hHP7d8bRtrmkNUqwU-YRXF9tL3NgEep1SA_JygrLUDg"
          }
        }
      ],
      holder: issuer.did,
      type: ["VerifiablePresentation", "CredentialFulfillment"],
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      proof: {
        type: "JwtProof2020"
        // jwt: "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iLCJDcmVkZW50aWFsRnVsZmlsbG1lbnQiXSwiaG9sZGVyIjoiZGlkOmtleTp6Nk1rbTFyWFNMWFRxazFUNzRhZmZUVFNTRGU5S1RzVUdDYnFqcmpVaUVydVZQN1ciLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6WyJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SWtwWFZDSjkuZXlKMll5STZleUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdk1qQXhPQzlqY21Wa1pXNTBhV0ZzY3k5Mk1TSXNJbWgwZEhCek9pOHZkbVZ5YVhSNUxtbGtMMmxrWlc1MGFYUjVJbDBzSW5SNWNHVWlPbHNpVm1WeWFXWnBZV0pzWlVOeVpXUmxiblJwWVd3aUxDSkxXVU5CVFV4QmRIUmxjM1JoZEdsdmJpSmRMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKTFdVTkJUVXhCZEhSbGMzUmhkR2x2YmlJNmV5SkFkSGx3WlNJNklrdFpRMEZOVEVGMGRHVnpkR0YwYVc5dUlpd2lZWFYwYUc5eWFYUjVTV1FpT2lKa2FXUTZkMlZpT25abGNtbDBlUzVwWkNJc0ltRndjSEp2ZG1Gc1JHRjBaU0k2SWpJd01qRXRNVEV0TVRKVU1UZzZOVFk2TVRZdU5UQTRXaUlzSW1GMWRHaHZjbWwwZVU1aGJXVWlPaUpXWlhKcGRIa2lMQ0poZFhSb2IzSnBkSGxWY213aU9pSm9kSFJ3Y3pvdkwzWmxjbWwwZVM1cFpDSXNJbUYxZEdodmNtbDBlVU5oYkd4aVlXTnJWWEpzSWpvaWFIUjBjSE02THk5cFpHVnVkR2wwZVM1MlpYSnBkSGt1YVdRaWZYMTlMQ0p6ZFdJaU9pSmthV1E2YTJWNU9ubzJUV3R5TVRKeVdreDZWWE5PTm1KeFJqaHFSMEpZUWxadE9HdExNemR4VFdwaFJHcFlhMU50VUZveGNFMWpZeUlzSW01aVppSTZNVFl6TmpjME16TTNOeXdpYVhOeklqb2laR2xrT210bGVUcDZOazFyYlRGeVdGTk1XRlJ4YXpGVU56UmhabVpVVkZOVFJHVTVTMVJ6VlVkRFluRnFjbXBWYVVWeWRWWlFOMWNpZlEuN3d3aUpNeEZCX3dtQjZkclpsVExMRTkwckVfT1Y1Q0VfbzQ4TGtEVkl0N2hIUDdkOGJSdHJta05VcXdVLVlSWEY5dEwzTmdFZXAxU0FfSnlnckxVRGciXX0sInN1YiI6ImRpZDprZXk6ejZNa20xclhTTFhUcWsxVDc0YWZmVFRTU0RlOUtUc1VHQ2JxanJqVWlFcnVWUDdXIiwiY3JlZGVudGlhbF9mdWxmaWxsbWVudCI6eyJpZCI6IjVmMjJmMWVhLTA0NDEtNDA0MS05MTZiLTI1MDRhMmE0MDc1YyIsIm1hbmlmZXN0X2lkIjoiS1lDQU1MQXR0ZXN0YXRpb24iLCJkZXNjcmlwdG9yX21hcCI6W3siaWQiOiJwcm9vZk9mSWRlbnRpZmllckNvbnRyb2xWUCIsImZvcm1hdCI6Imp3dF92YyIsInBhdGgiOiIkLnByZXNlbnRhdGlvbi5jcmVkZW50aWFsWzBdIn1dfSwiaXNzIjoiZGlkOmtleTp6Nk1rbTFyWFNMWFRxazFUNzRhZmZUVFNTRGU5S1RzVUdDYnFqcmpVaUVydVZQN1cifQ.T299mBMhBxfWtqvKSuGQ3tll2vLTfTJSTbMtpBduqHQdTCgbr8tQ4Pe2iXlGnCaIfw9PzNYUu3Y-44KSlEjfCg"
      }
    })
  })
})
