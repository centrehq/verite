import { verifyCredential, verifyPresentation } from "did-jwt-vc"
import type {
  JWT,
  JwtPresentationPayload,
  VerifiableCredential,
  RevocableCredential,
  RevocationListCredential,
  Verifiable,
  W3CCredential,
  W3CPresentation,
  RevocablePresentation
} from "../../types"
import { ValidationError } from "../errors"
import { didKeyResolver } from "./did-fns"

export function verifiablePresentationPayload(
  subject: string,
  vcJwt: VerifiableCredential | VerifiableCredential[] = []
): JwtPresentationPayload {
  return {
    sub: subject,
    vp: {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiablePresentation"],
      holder: subject,
      verifiableCredential: [vcJwt].flat()
    }
  }
}

/**
 * Decodes a JWT with a Verifiable Credential payload.
 */
export async function decodeVerifiableCredential(
  vcJwt: JWT
): Promise<
  Verifiable<W3CCredential> | RevocableCredential | RevocationListCredential
> {
  try {
    const res = await verifyCredential(vcJwt, didKeyResolver)
    return res.verifiableCredential
  } catch (err) {
    throw new ValidationError(
      "Input wasn't a valid Verifiable Credential",
      err.message,
      err
    )
  }
}

/**
 * Decode a JWT with a Verifiable Presentation payload.
 */
export async function decodeVerifiablePresentation(
  vpJwt: JWT
): Promise<Verifiable<W3CPresentation> | RevocablePresentation> {
  try {
    const res = await verifyPresentation(vpJwt, didKeyResolver)
    return res.verifiablePresentation
  } catch (err) {
    throw new ValidationError(
      "Input wasn't a valid Verifiable Presentation",
      err.message,
      err
    )
  }
}
