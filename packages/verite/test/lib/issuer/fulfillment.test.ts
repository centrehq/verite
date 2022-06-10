import { randomBytes } from "crypto"

import {
  buildCredentialApplication,
  decodeCredentialApplication
} from "../../../lib/issuer/credential-application"
import { buildAndSignFulfillment } from "../../../lib/issuer/credential-fulfillment"
import { buildKycAmlManifest } from "../../../lib/issuer/credential-manifest"
import { decodeVerifiablePresentation } from "../../../lib/utils"
import { buildIssuer, randomDidKey } from "../../../lib/utils/did-fns"
import { kycAmlAttestationFixture } from "../../fixtures/attestations"
import { revocationListFixture } from "../../fixtures/revocation-list"

describe("buildAndSignKycAmlFulfillment", () => {
  it("builds and signs a kyc/aml fulfillment", async () => {
    const issuerDidKey = await randomDidKey(randomBytes)
    const clientDidKey = await randomDidKey(randomBytes)
    const issuer = buildIssuer(issuerDidKey.subject, issuerDidKey.privateKey)
    const credentialIssuer = { id: issuer.did, name: "Verite" }
    const manifest = buildKycAmlManifest(credentialIssuer)
    const credentialApplication = await buildCredentialApplication(
      clientDidKey,
      manifest
    )
    const decodedApplication = await decodeCredentialApplication(
      credentialApplication
    )

    const encodedFulfillment = await buildAndSignFulfillment(
      issuer,
      decodedApplication.holder,
      decodedApplication.credential_application.manifest_id,
      decodedApplication.presentation_submission,
      kycAmlAttestationFixture,
      { credentialStatus: revocationListFixture }
    )
    const fulfillment = await decodeVerifiablePresentation(encodedFulfillment)
    expect(fulfillment.credential_fulfillment).toBeDefined()
    expect(fulfillment.credential_fulfillment.manifest_id).toEqual(
      "KYCAMLAttestation"
    )
  })
})
