import {
  buildAndSignFulfillment,
  decodeCredentialApplication,
  EncodedCredentialApplication,
  EncodedCredentialFulfillment,
  RevocableCredential,
  ValidationError
} from "@centre/verity"
import {
  buildIssuer,
  revokeCredential,
  decodeVerifiablePresentation,
  getManifestIdFromCredentialApplication,
  validateCredentialApplication
} from "@centre/verity"
import { apiHandler, methodNotAllowed, notFound } from "../../../../lib/api-fns"
import { findUserFromTemporaryAuthToken, User } from "../../../../lib/database"
import {
  allRevocationLists,
  saveRevocationList,
  findCredentialsByUserIdAndType,
  generateRevocationListStatus,
  storeRevocableCredential
} from "../../../../lib/database"
import { fulfillmentDataForUser } from "../../../../lib/issuance/fulfillment"
import { findManifestById } from "../../../../lib/manifest"

/**
 * Handle a POST request to containing an empty Verifiable Presentation proving
 * ownership of a client did.  The endpoint checks the validity of the Verifiable
 * Presentation, and issues a separate Verifiable Presentation containing
 * the Verifiable Credentials for this given user.
 */
export default apiHandler<EncodedCredentialFulfillment>(async (req, res) => {
  // Only allow POST requests to this endpoint
  if (req.method !== "POST") {
    return methodNotAllowed(res)
  }

  // Find the user record from a temporary auth token
  // We need to use a temporary auth token because this submission endpoint
  // may not be called directly from the user's browser (e.g. via mobile wallet)
  const user = await findUserFromTemporaryAuthToken(req.query.token as string)
  if (!user) {
    return notFound(res)
  }

  const credentialApplication: EncodedCredentialApplication = req.body

  // Ensure we have a valid manifest
  const manifest = await findManifestById(
    getManifestIdFromCredentialApplication(credentialApplication)
  )
  if (!manifest) {
    throw new ValidationError(
      "Invalid Manifest ID",
      "This issuer doesn't issue credentials for the specified Manifest ID"
    )
  }

  // Decode the Verifiable Presentation and check the signature
  const decodedCredentialApplication = await decodeCredentialApplication(
    credentialApplication
  )

  // Validate the format and contents of the credential application
  validateCredentialApplication(decodedCredentialApplication)

  // Before we issue a new credential of this type to a user, revoke all their
  // previous credentials of the same type.
  await revokeUserCredentials(user, manifest.id)

  // Generate new credentials for the user
  const fulfillment = await buildAndSignFulfillment(
    buildIssuer(process.env.ISSUER_DID, process.env.ISSUER_SECRET),
    decodedCredentialApplication,
    await generateRevocationListStatus(),
    fulfillmentDataForUser(user, manifest)
  )

  // Save the credentials to the database
  await persistGeneratedCredentials(user, fulfillment)

  res.json(fulfillment)
})

/**
 * Persist the verifiable credential to the database, associated with the user.
 */
async function persistGeneratedCredentials(
  user: User,
  fulfillment: EncodedCredentialFulfillment
): Promise<void> {
  const decodedPresentation = await decodeVerifiablePresentation(
    fulfillment.presentation
  )

  const decodedCredential =
    decodedPresentation.verifiableCredential as RevocableCredential[]

  await storeRevocableCredential(decodedCredential, user.id)
}

/**
 * Revokes all the credentials for a given user and type.
 *
 * @param user
 * @param type
 */
async function revokeUserCredentials(user: User, type: string) {
  const credentials = await findCredentialsByUserIdAndType(user.id, type)

  for (const credential of credentials) {
    // Find the credential's revocation list
    const url = credential.credentialStatus.statusListCredential
    const revocationLists = await allRevocationLists()
    const revocationList = revocationLists.find((l) => l.id === url)

    // Revoke the credential
    const list = await revokeCredential(
      credential,
      revocationList,
      buildIssuer(process.env.ISSUER_DID, process.env.ISSUER_SECRET)
    )

    // Persist the new revocation list
    await saveRevocationList(list)
  }
}
