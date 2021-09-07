import { createVerificationSubmission } from "../../../lib/client/verification-submission"
import {
  createCredentialApplication,
  decodeCredentialApplication
} from "../../../lib/credential-application-fns"
import { ValidationError } from "../../../lib/errors"
import { buildAndSignFulfillment } from "../../../lib/issuer/fulfillment"
import { decodeVerifiablePresentation } from "../../../lib/utils/credentials"
import { randomDidKey } from "../../../lib/utils/did-fns"
import { validateCredentialApplication } from "../../../lib/validators/validate-credential-application"
import { validateVerificationSubmission } from "../../../lib/validators/validate-verification-submission"
import { generateVerificationRequest } from "../../../lib/waci"
import type {
  EncodedVerificationSubmission,
  VerificationRequest
} from "../../../types"
import {
  creditScoreAttestationFixture,
  kycAmlAttestationFixture
} from "../../fixtures/attestations"
import { revocationListFixture } from "../../fixtures/revocation-list"
import { generateManifestAndIssuer } from "../../support/manifest-fns"

describe("Submission validator", () => {
  it("validates a KYC Verification Submission", async () => {
    const clientDidKey = await randomDidKey()
    const verifierDidKey = await randomDidKey()
    const { manifest, issuer } = await generateManifestAndIssuer()
    const application = await createCredentialApplication(
      clientDidKey,
      manifest
    )

    await validateCredentialApplication(application, manifest)

    const decodedApplication = await decodeCredentialApplication(application)

    const fulfillment = await buildAndSignFulfillment(
      issuer,
      decodedApplication,
      kycAmlAttestationFixture,
      { credentialStatus: revocationListFixture }
    )

    const fulfillmentVP = await decodeVerifiablePresentation(
      fulfillment.presentation
    )
    const clientVC = fulfillmentVP.verifiableCredential![0]

    const verificationRequest = generateVerificationRequest(
      "KYCAMLAttestation",
      verifierDidKey.controller,
      "https://test.host/verify",
      "https://other.host/callback",
      [issuer.did]
    )

    const submission = await createVerificationSubmission(
      clientDidKey,
      verificationRequest.body.presentation_definition,
      clientVC
    )

    await expect(
      validateVerificationSubmission(
        submission,
        verificationRequest.body.presentation_definition
      )
    ).resolves.not.toThrow()
  })

  it("validates a Credit Score Verification Submission", async () => {
    const clientDidKey = await randomDidKey()
    const verifierDidKey = await randomDidKey()
    const { manifest, issuer } = await generateManifestAndIssuer("creditScore")
    const application = await createCredentialApplication(
      clientDidKey,
      manifest
    )

    await validateCredentialApplication(application, manifest)

    const decodedApplication = await decodeCredentialApplication(application)

    const fulfillment = await buildAndSignFulfillment(
      issuer,
      decodedApplication,
      creditScoreAttestationFixture
    )

    const fulfillmentVP = await decodeVerifiablePresentation(
      fulfillment.presentation
    )
    const clientVC = fulfillmentVP.verifiableCredential![0]

    const verificationRequest = generateVerificationRequest(
      "CreditScoreAttestation",
      verifierDidKey.controller,
      "https://test.host/verify",
      "https://other.host/callback",
      [issuer.did],
      { minimumCreditScore: creditScoreAttestationFixture.score }
    )

    const submission = await createVerificationSubmission(
      clientDidKey,
      verificationRequest.body.presentation_definition,
      clientVC
    )

    await expect(
      validateVerificationSubmission(
        submission,
        verificationRequest.body.presentation_definition
      )
    ).resolves.not.toThrow()
  })

  it("rejects if the issuer is not trusted", async () => {
    const clientDidKey = await randomDidKey()
    const verifierDidKey = await randomDidKey()
    const { manifest, issuer } = await generateManifestAndIssuer()
    const application = await createCredentialApplication(
      clientDidKey,
      manifest
    )

    await validateCredentialApplication(application, manifest)

    const decodedApplication = await decodeCredentialApplication(application)

    const fulfillment = await buildAndSignFulfillment(
      issuer,
      decodedApplication,
      kycAmlAttestationFixture,
      { credentialStatus: revocationListFixture }
    )

    const fulfillmentVP = await decodeVerifiablePresentation(
      fulfillment.presentation
    )
    const clientVC = fulfillmentVP.verifiableCredential![0]

    const verificationRequest = generateVerificationRequest(
      "KYCAMLAttestation",
      verifierDidKey.controller,
      "https://test.host/verify",
      "https://other.host/callback",
      ["NOT TRUSTED"]
    )

    const submission = await createVerificationSubmission(
      clientDidKey,
      verificationRequest.body.presentation_definition,
      clientVC
    )

    await expectValidationError(
      submission,
      verificationRequest,
      "Credential did not match constraint: We can only verify credentials attested by a trusted authority."
    )
  })

  it("rejects if the credit score is too low", async () => {
    const clientDidKey = await randomDidKey()
    const verifierDidKey = await randomDidKey()
    const { manifest, issuer } = await generateManifestAndIssuer("creditScore")
    const application = await createCredentialApplication(
      clientDidKey,
      manifest
    )

    await validateCredentialApplication(application, manifest)

    const decodedApplication = await decodeCredentialApplication(application)

    const fulfillment = await buildAndSignFulfillment(
      issuer,
      decodedApplication,
      creditScoreAttestationFixture
    )

    const minimumCreditScore = creditScoreAttestationFixture.score + 1
    const fulfillmentVP = await decodeVerifiablePresentation(
      fulfillment.presentation
    )
    const clientVC = fulfillmentVP.verifiableCredential![0]

    const verificationRequest = generateVerificationRequest(
      "CreditScoreAttestation",
      verifierDidKey.controller,
      "https://test.host/verify",
      "https://other.host/callback",
      [issuer.did],
      { minimumCreditScore }
    )

    const submission = await createVerificationSubmission(
      clientDidKey,
      verificationRequest.body.presentation_definition,
      clientVC
    )

    await expectValidationError(
      submission,
      verificationRequest,
      `Credential did not match constraint: We can only verify Credit Score credentials that are above ${minimumCreditScore}.`
    )
  })

  it("rejects if the submission includes a KYC credential when a Credit Score is required", async () => {
    const clientDidKey = await randomDidKey()
    const verifierDidKey = await randomDidKey()
    const { manifest, issuer } = await generateManifestAndIssuer("kyc")
    const application = await createCredentialApplication(
      clientDidKey,
      manifest
    )

    await validateCredentialApplication(application, manifest)

    const decodedApplication = await decodeCredentialApplication(application)

    const fulfillment = await buildAndSignFulfillment(
      issuer,
      decodedApplication,
      kycAmlAttestationFixture,
      { credentialStatus: revocationListFixture }
    )

    const fulfillmentVP = await decodeVerifiablePresentation(
      fulfillment.presentation
    )
    const clientVC = fulfillmentVP.verifiableCredential![0]

    // Generate Credit Score Request, even though we have a KYC credential
    const verificationRequest = generateVerificationRequest(
      "CreditScoreAttestation",
      verifierDidKey.controller,
      "https://test.host/verify",
      "https://other.host/callback",
      [issuer.did]
    )

    const submission = await createVerificationSubmission(
      clientDidKey,
      verificationRequest.body.presentation_definition,
      clientVC
    )

    await expectValidationError(
      submission,
      verificationRequest,
      "Credential did not match constraint: The Credit Score Attestation requires the field: 'score'."
    )
  })
})

async function expectValidationError(
  submission: EncodedVerificationSubmission,
  verificationRequest: VerificationRequest,
  message: string
): Promise<void> {
  let error: ValidationError | undefined

  try {
    await validateVerificationSubmission(
      submission,
      verificationRequest.body.presentation_definition
    )
  } catch (e) {
    error = e as ValidationError
  }

  expect(error).toBeDefined()
  expect(error!.details).toEqual(message)
}
