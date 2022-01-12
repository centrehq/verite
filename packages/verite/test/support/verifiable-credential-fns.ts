import { buildAndSignVerifiableCredential } from "../../lib/issuer/credential-fulfillment"
import {
  buildIssuer,
  decodeVerifiableCredential,
  randomDidKey
} from "../../lib/utils"
import type { Verifiable, W3CCredential } from "../../types/DidJwt"
import { creditScoreAttestationFixture } from "../fixtures/attestations"

export async function generateVerifiableCredential(): Promise<
  Verifiable<W3CCredential>
> {
  const didKey = randomDidKey()
  const signer = buildIssuer(didKey.subject, didKey.privateKey)
  const jwt = await buildAndSignVerifiableCredential(
    signer,
    signer.did,
    creditScoreAttestationFixture
  )

  return decodeVerifiableCredential(jwt)
}
