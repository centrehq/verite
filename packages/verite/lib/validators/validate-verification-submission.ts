import Ajv from "ajv"
import jsonpath from "jsonpath"

import { ValidationError } from "../errors"
import { isRevoked } from "../issuer"
import { asyncSome, decodeVerifiablePresentation, isExpired } from "../utils"
import { findSchemaById, validateAttestationSchema } from "./validate-schema"

import type {
  DecodedPresentationSubmission,
  InputDescriptor,
  PresentationDefinition,
  DecodedCredentialApplication,
  W3CCredential,
  W3CPresentation,
  Verifiable,
  InputDescriptorConstraintField
} from "../../types"
import type { JWT, VerifyPresentationOptions } from "did-jwt-vc/src/types"

const ajv = new Ajv()

/**
 * Find the first path in the input descriptor field which is present in the
 * credential.
 */
function findFirstMatchingPathForField(
  field: InputDescriptorConstraintField,
  credential: Verifiable<W3CCredential>
): unknown | undefined {
  for (const path of field.path) {
    const value = jsonpath.query(credential, path)
    if (value.length) {
      return value[0]
    }
  }
}

/**
 * Validate a credential against a given input descriptor field constraints
 */
function validateField(
  field: InputDescriptorConstraintField,
  credential: Verifiable<W3CCredential>
): boolean {
  const value = findFirstMatchingPathForField(field, credential)
  if (!value) {
    // FAIL, no matching paths
    return false
  }

  if (!field.filter) {
    // PASS, no filter. Anything is valid
    return true
  }

  ajv.validate(field.filter, value)
  return !ajv.errors
}

/**
 * Validate all input descriptors against their constraints in the
 * verification request presentation definition
 */
function validateInputDescriptors(
  credentialMap: Map<string, Verifiable<W3CCredential>[]>,
  descriptors?: InputDescriptor[]
): void {
  if (!descriptors) {
    // no input descriptors, so there is nothing to validate
    return
  }

  // iterate over all input descriptors to find the relevant credentials
  descriptors.forEach((descriptor) => {
    const constraints = descriptor.constraints
    const fields = constraints?.fields

    if (!constraints || !fields || !fields.length) {
      // no constraints on this descriptor, so everything is valid
      return
    }

    const credentials = credentialMap.get(descriptor.id)

    if (!credentials || !credentials.length) {
      // no credentials found for this schema, nothing to validate
      return
    }

    credentials.forEach((credential) => {
      // iterate over each field in the constraint and validate it against
      // the credential.
      fields.forEach((field) => {
        if (!validateField(field, credential)) {
          throw new ValidationError(
            `Credential failed to meet criteria specified by input descriptor ${descriptor.id}`,
            `Credential did not match constraint: ${field.purpose}`
          )
        }
      })
    })
  })
}

/**
 * Generate a mapping from input descriptors to to a list of all matching
 * credentials from the submission.
 */
function mapInputsToDescriptors(
  submission: DecodedPresentationSubmission | DecodedCredentialApplication,
  inputDescriptors?: InputDescriptor[] | undefined
): Map<string, Verifiable<W3CCredential>[]> {
  const descriptorMap = submission.presentation_submission?.descriptor_map ?? []

  return descriptorMap.reduce((map, d) => {
    const match = inputDescriptors?.find((id) => id.id === d.id)

    if (!match) {
      return map
    }

    const credentials = jsonpath.query(submission, d.path)
    return map.set(match.id, credentials)
  }, new Map<string, Verifiable<W3CCredential>[]>())
}

/**
 * Ensure all credentials in a verifiable presentation are not revoked
 */
async function ensureNotRevoked(
  presentation: Verifiable<W3CPresentation>
): Promise<void> {
  const anyRevoked = await asyncSome(
    presentation.verifiableCredential ?? [],
    async (credential) => {
      return isRevoked(credential)
    }
  )

  if (anyRevoked) {
    throw new ValidationError(
      "Revoked Credential",
      "The selected verified credential has been revoked"
    )
  }
}

/**
 * Ensure all credentials in a verifiable presentation are not expired
 */
function ensureNotExpired(presentation: Verifiable<W3CPresentation>): void {
  const credentials = presentation.verifiableCredential || []

  const anyExpired = credentials.some((credential) => isExpired(credential))

  if (anyExpired) {
    throw new ValidationError(
      "Expired Credential",
      "The selected verified credential has expired"
    )
  }
}

function validateCredentialAgainstSchema(
  credentialMap: Map<string, Verifiable<W3CCredential>[]>,
  descriptors?: InputDescriptor[]
): void {
  if (!descriptors) {
    // no input descriptors, so there is nothing to validate
    return
  }

  // iterate over all input descriptors to find the relevant credentials
  descriptors.forEach((descriptor) => {
    const credentials = credentialMap.get(descriptor.id)

    const schema = findSchemaById(descriptor.schema[0].uri)

    if (!schema) {
      throw new ValidationError(`Unknown schema: ${descriptor.schema[0].uri}`)
    }

    credentials?.forEach((credential) => {
      const type = credential.type[credential.type.length - 1]
      validateAttestationSchema(credential.credentialSubject[type], schema)
    })
  })
}

/**
 * The Presentation Exchange spec includes an `is_holder` constraint.
 * We can use that property to find the fields that must match the holder.
 *
 * In this demo, we use it to ensure that the holder, or person submitting
 * the presentation is the subject of the credential. This will ensure that
 * no one can use someone else's credential.
 *
 * The spec is a mildly convoluted, allowing multiple is_holder properties,
 * each with multiple fields that map to input descriptors by id, and then
 * the input descriptors mapping to actual values in the credential with
 * json paths.
 *
 * A more simple implementation would look like this if one did not want to
 * support the is_holder property:
 *
 * const holder = presentation.holder
 * const subject = presentation.verifiableCredential[0].credentialSubject.id
 *  if (holder !== subject) {
 *    throw new ValidationError(
 *      "Signing Error",
 *      "Presentation is not signed by the subject."
 *    )
 *  }
 */
async function ensureHolderIsSubject(
  credentialMap: Map<string, Verifiable<W3CCredential>[]>,
  holder: string,
  inputDescriptors: InputDescriptor[]
): Promise<void> {
  inputDescriptors.forEach((descriptor) => {
    // Each input descriptor can have an is_holder property.
    const isHolders = descriptor.constraints?.is_holder
    if (isHolders) {
      isHolders.forEach((isHolder) => {
        //
        const fieldIds = isHolder.field_id
        fieldIds.forEach((fieldId) => {
          // Find the fields with matching ids
          const fields = descriptor.constraints?.fields?.filter((field) => {
            return field.id === fieldId
          })
          fields?.forEach((field) => {
            const credentials = credentialMap.get(descriptor.id)
            credentials?.forEach((credential) => {
              const value = findFirstMatchingPathForField(field, credential)
              if (holder !== value) {
                throw new ValidationError(
                  "Invalid Credential",
                  "Presentation holder is not the subject."
                )
              }
            })
          })
        })
      })
    }
  })
}

/**
 * Validate a verifiable presentation against a presentation definition
 */
export async function validateVerificationSubmission(
  submission: JWT,
  inputDescriptors: InputDescriptor[],
  options?: VerifyPresentationOptions
): Promise<void> {
  const presentation = await decodeVerifiablePresentation(submission, options)

  /**
   * Check the verifiable credentials to ensure non are revoked. To check
   * revocation status, we must either have a local cached copy of the revocation
   * list, or fetch the list from the location described in the credential.
   */
  await ensureNotRevoked(presentation)

  /**
   * Check the verifiable credentials to ensure none are expired. Generally,
   * the JWT verification itself would handle this by checking the `exp` field
   * of the JWT, but those JWT properties are only checked on the Presentation
   * JWT, and not on the included credentials themselves.
   *
   * To ensure we do not use any expired credentials, we check this ourselves
   * here.
   */
  ensureNotExpired(presentation)

  const credentialMap = mapInputsToDescriptors(presentation, inputDescriptors)
  /**
   * Check that the Verified Presentation was signed by the subject of the
   * Verified Credential. This ensures that the person submitting the
   * Presentation is the credential subject.
   */
  await ensureHolderIsSubject(credentialMap, presentation.holder, inputDescriptors)

  /**
   * Check the verifiable credentials to ensure they meet the requirements
   * set forward in the verification request. This check will generally ensure
   * the credential is signed by a trusted signer, and meets the minimum
   * requirements set forth in the request (e.g. minimum credit score).
   */
  validateInputDescriptors(credentialMap, inputDescriptors)

  /**
   * Validate that each credential matches the expected schema
   */
  validateCredentialAgainstSchema(credentialMap, inputDescriptors)
}
