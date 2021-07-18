import { createUser } from "lib/database"
import { createKycAmlFulfillment } from "lib/issuance/fulfillment"
import { findManifestById } from "lib/issuance/manifest"
import { validateCredentialSubmission } from "lib/issuance/submission"
import { credentialSigner } from "lib/signer"
import { kycVerificationRequest } from "lib/verification/requests"
import { validateVerificationSubmission } from "lib/verification/submission"
import {
  createCredentialApplication,
  createPresentationSubmission,
  decodeVerifiablePresentation,
  randomDidKey,
} from "lib/verity"

describe("verification", () => {
  it("just works", async () => {
    // 0. PREREQ: Ensure client has a valid KYC credential
    const clientDidKey = await randomDidKey()
    const kycManifest = findManifestById("KYCAMLAttestation")
    const user = createUser("test@test.com", { jumioScore: 55, ofacScore: 2 })
    const application = await createCredentialApplication(
      clientDidKey,
      kycManifest
    )
    const acceptedApplication = await validateCredentialSubmission(application)
    const fulfillment = await createKycAmlFulfillment(
      user,
      credentialSigner,
      acceptedApplication
    )

    const fulfillmentVP = await decodeVerifiablePresentation(
      fulfillment.presentation
    )
    const clientVC = fulfillmentVP.payload.vp.verifiableCredential[0]

    // 2. VERIFIER: Discovery of verification requirements
    const kycRequest = kycVerificationRequest()

    // 3. CLIENT: Create verification submission (wraps a presentation submission)
    const submission = await createPresentationSubmission(
      clientDidKey,
      kycRequest.presentation_definition,
      clientVC
    )

    expect(submission.presentation_submission.descriptor_map).toEqual([
      {
        id: "kycaml_input",
        format: "jwt_vc",
        path: "$.presentation.verifiableCredential[0]"
      }
    ])

    // 4. VERIFIER: Verifies submission
    const result = await validateVerificationSubmission(submission)
    expect(result).toBeDefined()
  })

  it("rejects an expired input", async () => {
    /*
    expect.assertions(1)

    const clientDidKey = await randomDidKey()
    const kycManifest = findManifestById("KYCAMLAttestation")
    const application = await createCredentialApplication(
      clientDidKey,
      kycManifest
    )

    // overwrite with expired VP
    application.presentation = expiredPresentation

    await expect(
      validateCredentialSubmission(application)
    ).rejects.toThrowError(VerificationError)*/
  })
})
