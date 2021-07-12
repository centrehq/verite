import { EdDSASigner } from "did-jwt"
import {
  JwtCredentialPayload,
  verifyCredential,
  JwtPresentationPayload,
  Issuer
} from "did-jwt-vc"
import {
  JWT,
  VerifiedCredential,
  VerifiedPresentation
} from "did-jwt-vc/lib/types"
import { DidKey, resolver } from "./didKey"
import {verifyPresentation } from "./sign-utils"

export const vpPayloadApplication = (subject: Issuer): JwtPresentationPayload => {
  return {
    iss: subject.did,
    sub: subject.did,
    vp: {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiablePresentation"],
      verifiableCredential: [], // TODO: why required?
      holder: subject.did
    }
  }
}

export const vcPayloadKYCFulfillment = (
  subject: string,
  kycAttestation: Record<string, unknown>
): JwtCredentialPayload => {
  return {
    sub: subject,
    vc: {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://centre.io/identity"
      ],
      type: ["VerifiableCredential", "KYCAMLAttestation"],
      credentialSubject: {
        KYCAMLAttestation: kycAttestation,
        id: subject
      }
    }
  }
}

/**
 * Decodes a JWT with a Verifiable Credential payload.
 */
export const decodeVc = (vc: JWT): Promise<VerifiedCredential> => {
  return verifyCredential(vc, resolver)
}

export function vpPayload(vcJwt: JWT | JWT[]): JwtPresentationPayload {
  return {
    vp: {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiablePresentation"],
      verifiableCredential: [vcJwt].flat()
    }
  }
}

/**
 * Decode a JWT with a Verifiable Presentation payload.
 */
export const decodeVp = async (vpJwt: JWT): Promise<VerifiedPresentation> => {
  return verifyPresentation(vpJwt, resolver)
}

export function issuerFromDid(did: DidKey): Issuer {
  return {
    did: did.controller,
    signer: EdDSASigner(did.privateKey),
    alg: "EdDSA"
  }
}
