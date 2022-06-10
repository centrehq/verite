import { randomBytes } from "crypto"
import { v4 as uuidv4 } from "uuid"

import { buildCredentialApplication } from "../../lib/issuer/credential-application"
import { buildAndSignFulfillment } from "../../lib/issuer/credential-fulfillment"
import { decodeVerifiablePresentation } from "../../lib/utils/credentials"
import { randomDidKey } from "../../lib/utils/did-fns"
import { validateCredentialApplication } from "../../lib/validators/validate-credential-application"
import { validateVerificationSubmission } from "../../lib/validators/validate-verification-submission"
import { buildPresentationSubmission } from "../../lib/verifier/presentation-submission"
import { buildKycVerificationOffer } from "../../lib/verifier/verification-offer"
import {
  DecodedCredentialApplication,
  DidKey,
  RevocableCredential
} from "../../types"
import { kycAmlAttestationFixture } from "../fixtures/attestations"
import { revocationListFixture } from "../fixtures/revocation-list"
import { generateManifestAndIssuer } from "../support/manifest-fns"

describe("verification", () => {
  it("accepts and validates a verification submission containing credentials", async () => {
    // 1. Ensure client has Verifiable Credentials
    const verifierDidKey = await randomDidKey(randomBytes)
    const clientDidKey = await randomDidKey(randomBytes)
    const verifiableCredentials = await getClientVerifiableCredential(
      clientDidKey
    )

    // 2. VERIFIER: Discovery of verification requirements
    const kycRequest = buildKycVerificationOffer(
      uuidv4(),
      verifierDidKey.subject,
      "https://test.host/verify"
    )

    // 3. CLIENT: Create verification submission (wraps a presentation submission)
    const encodedSubmission = await buildPresentationSubmission(
      clientDidKey,
      kycRequest.body.presentation_definition,
      verifiableCredentials
    )
    const submission = await decodeVerifiablePresentation(encodedSubmission)

    expect(submission.presentation_submission!.descriptor_map).toEqual([
      {
        id: "kycaml_input",
        format: "jwt_vc",
        path: "$.verifiableCredential[0]"
      }
    ])

    // 4. VERIFIER: Verifies submission
    await validateVerificationSubmission(
      encodedSubmission,
      kycRequest.body.presentation_definition.input_descriptors
    )
  })
})

async function getClientVerifiableCredential(
  clientDidKey: DidKey
): Promise<RevocableCredential[]> {
  const { manifest, issuer } = await generateManifestAndIssuer()

  // 0. PREREQ: Ensure client has a valid KYC credential
  const encodedApplication = await buildCredentialApplication(
    clientDidKey,
    manifest
  )
  const application = (await decodeVerifiablePresentation(
    encodedApplication
  )) as DecodedCredentialApplication
  await validateCredentialApplication(application, manifest)

  const fulfillment = await buildAndSignFulfillment(
    issuer,
    application.holder,
    application.credential_application.manifest_id,
    application.presentation_submission,
    kycAmlAttestationFixture,
    { credentialStatus: revocationListFixture }
  )

  const fulfillmentVP = await decodeVerifiablePresentation(fulfillment)

  return fulfillmentVP.verifiableCredential as RevocableCredential[]
}
