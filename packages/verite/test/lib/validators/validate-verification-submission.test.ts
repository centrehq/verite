import { randomBytes } from "crypto"
import { v4 as uuidv4 } from "uuid"

import { ValidationError } from "../../../lib/errors"
import { buildCredentialApplication } from "../../../lib/issuer/credential-application"
import { buildAndSignFulfillment } from "../../../lib/issuer/credential-fulfillment"
import { decodeVerifiablePresentation } from "../../../lib/utils/credentials"
import { randomDidKey } from "../../../lib/utils/did-fns"
import { validateCredentialApplication } from "../../../lib/validators/validate-credential-application"
import { validateVerificationSubmission } from "../../../lib/validators/validate-verification-submission"
import { buildPresentationSubmission } from "../../../lib/verifier/presentation-submission"
import {
  buildCreditScoreVerificationOffer,
  buildKycVerificationOffer
} from "../../../lib/verifier/verification-offer"
import {
  creditScoreAttestationFixture,
  kycAmlAttestationFixture
} from "../../fixtures/attestations"
import { revocationListFixture } from "../../fixtures/revocation-list"
import { generateManifestAndIssuer } from "../../support/manifest-fns"

import type {
  DecodedCredentialApplication,
  EncodedPresentationSubmission,
  VerificationOffer
} from "../../../types"

describe("Submission validator", () => {
  it("validates a KYC Verification Submission", async () => {
    const clientDidKey = randomDidKey(randomBytes)
    const verifierDidKey = randomDidKey(randomBytes)
    const { manifest, issuer } = await generateManifestAndIssuer()
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
    const clientVC = fulfillmentVP.verifiableCredential![0]

    const verificationRequest = buildKycVerificationOffer(
      uuidv4(),
      verifierDidKey.subject,
      "https://test.host/verify",
      "https://other.host/callback",
      [issuer.did]
    )

    const submission = await buildPresentationSubmission(
      clientDidKey,
      verificationRequest.body.presentation_definition,
      clientVC
    )

    await expect(
      validateVerificationSubmission(
        submission,
        verificationRequest.body.presentation_definition.input_descriptors
      )
    ).resolves.not.toThrow()
  })

  it("validates a Credit Score Verification Submission", async () => {
    const clientDidKey = randomDidKey(randomBytes)
    const verifierDidKey = randomDidKey(randomBytes)
    const { manifest, issuer } = await generateManifestAndIssuer("creditScore")
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
      creditScoreAttestationFixture
    )

    const fulfillmentVP = await decodeVerifiablePresentation(fulfillment)
    const clientVC = fulfillmentVP.verifiableCredential![0]

    const verificationRequest = buildCreditScoreVerificationOffer(
      uuidv4(),
      verifierDidKey.subject,
      "https://test.host/verify",
      "https://other.host/callback",
      [issuer.did],
      creditScoreAttestationFixture.score
    )

    const submission = await buildPresentationSubmission(
      clientDidKey,
      verificationRequest.body.presentation_definition,
      clientVC
    )

    await expect(
      validateVerificationSubmission(
        submission,
        verificationRequest.body.presentation_definition.input_descriptors
      )
    ).resolves.not.toThrow()
  })

  it("rejects if the issuer is not trusted", async () => {
    const clientDidKey = randomDidKey(randomBytes)
    const verifierDidKey = randomDidKey(randomBytes)
    const { manifest, issuer } = await generateManifestAndIssuer()
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
    const clientVC = fulfillmentVP.verifiableCredential![0]

    const verificationRequest = buildKycVerificationOffer(
      uuidv4(),
      verifierDidKey.subject,
      "https://test.host/verify",
      "https://other.host/callback",
      ["NOT TRUSTED"]
    )

    const submission = await buildPresentationSubmission(
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
    const clientDidKey = randomDidKey(randomBytes)
    const verifierDidKey = randomDidKey(randomBytes)
    const { manifest, issuer } = await generateManifestAndIssuer("creditScore")
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
      creditScoreAttestationFixture
    )

    const minimumCreditScore = creditScoreAttestationFixture.score + 1
    const fulfillmentVP = await decodeVerifiablePresentation(fulfillment)
    const clientVC = fulfillmentVP.verifiableCredential![0]

    const verificationRequest = buildCreditScoreVerificationOffer(
      uuidv4(),
      verifierDidKey.subject,
      "https://test.host/verify",
      "https://other.host/callback",
      [issuer.did],
      minimumCreditScore
    )

    const submission = await buildPresentationSubmission(
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
    const clientDidKey = randomDidKey(randomBytes)
    const verifierDidKey = randomDidKey(randomBytes)
    const { manifest, issuer } = await generateManifestAndIssuer("kyc")
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
    const clientVC = fulfillmentVP.verifiableCredential![0]

    // Generate Credit Score Request, even though we have a KYC credential
    const verificationRequest = buildCreditScoreVerificationOffer(
      uuidv4(),
      verifierDidKey.subject,
      "https://test.host/verify",
      "https://other.host/callback",
      [issuer.did]
    )

    const submission = await buildPresentationSubmission(
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

  it("rejects if the submission is not signed by the subject", async () => {
    const clientDidKey = randomDidKey(randomBytes)
    const verifierDidKey = randomDidKey(randomBytes)
    const { manifest, issuer } = await generateManifestAndIssuer()
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
    const clientVC = fulfillmentVP.verifiableCredential![0]

    const verificationRequest = buildKycVerificationOffer(
      uuidv4(),
      verifierDidKey.subject,
      "https://test.host/verify",
      "https://other.host/callback",
      [issuer.did]
    )

    const differentHolderThanSubject = randomDidKey(randomBytes)
    const submission = await buildPresentationSubmission(
      differentHolderThanSubject,
      verificationRequest.body.presentation_definition,
      clientVC
    )

    await expectValidationError(
      submission,
      verificationRequest,
      "Presentation holder is not the subject."
    )
  })
})

async function expectValidationError(
  submission: EncodedPresentationSubmission,
  verificationRequest: VerificationOffer,
  message: string
): Promise<void> {
  let error: ValidationError | undefined

  try {
    await validateVerificationSubmission(
      submission,
      verificationRequest.body.presentation_definition.input_descriptors
    )
  } catch (e) {
    error = e as ValidationError
  }

  expect(error).toBeDefined()
  expect(error!.details).toEqual(message)
}
