import { isString } from "lodash"
import { v4 as uuidv4 } from "uuid"

import {
  encodeVerifiableCredential,
  encodeVerifiablePresentation
} from "../utils/credentials"

import type {
  DescriptorMap,
  EncodedCredentialFulfillment,
  Issuer,
  KYCAMLAttestation,
  DecodedCredentialApplication,
  CreditScoreAttestation,
  CredentialPayload,
  DidKey,
  JWT,
  PresentationSubmission
} from "../../types"
import type {
  CreateCredentialOptions,
  CreatePresentationOptions
} from "did-jwt-vc/src/types"

/**
 * Build a VerifiableCredential containing an attestation for the given holder.
 */
export async function buildAndSignVerifiableCredential(
  signer: Issuer,
  subject: string | DidKey,
  attestation: KYCAMLAttestation | CreditScoreAttestation,
  payload: Partial<CredentialPayload> = {},
  options?: CreateCredentialOptions
): Promise<JWT> {
  const type = attestation["type"]
  const subjectId = isString(subject) ? subject : subject.subject

  const vcPayload: CredentialPayload = Object.assign(
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        { "@vocab": "https://verite.id/identity/" }
      ],
      type: ["VerifiableCredential", type],
      credentialSubject: {
        id: subjectId,
        [type]: attestation
      },
      issuanceDate: new Date(),
      issuer: { id: signer.did }
    },
    payload
  )

  return encodeVerifiableCredential(vcPayload, signer, options)
}

/**
 * Build a VerifiablePresentation containing a list of attestations (VerifiableCredentials)
 */
export async function buildAndSignFulfillment(
  signer: Issuer,
  holder: string,
  credentialManifestId: string, 
  presentationSubmission: PresentationSubmission | undefined,
  attestation: KYCAMLAttestation | CreditScoreAttestation,
  payload: Partial<CredentialPayload> = {},
  options?: CreatePresentationOptions
): Promise<EncodedCredentialFulfillment> {
  const encodedCredentials = await buildAndSignVerifiableCredential(
    signer,
    holder,
    attestation,
    payload
  )

  const encodedPresentation = await encodeVerifiablePresentation(
    signer.did,
    encodedCredentials,
    signer,
    options,
    ["VerifiablePresentation", "CredentialFulfillment"],
    {
      credential_fulfillment: {
        id: uuidv4(),
        manifest_id: credentialManifestId,
        descriptor_map:
        presentationSubmission?.descriptor_map?.map<DescriptorMap>(
            (d, i) => {
              return {
                id: d.id,
                format: "jwt_vc",
                path: `$.presentation.credential[${i}]`
              }
            }
          ) ?? []
      }
    }
  )

  return encodedPresentation as unknown as EncodedCredentialFulfillment
}
