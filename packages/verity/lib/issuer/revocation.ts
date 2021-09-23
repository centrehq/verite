import fetch from "isomorphic-unfetch"
import { has } from "lodash"
import type {
  CredentialPayload,
  Issuer,
  MaybeRevocableCredential,
  RevocableCredential,
  RevocationList,
  RevocationListCredential,
  Verifiable,
  W3CCredential
} from "../../types"
import {
  encodeVerifiableCredential,
  decodeVerifiableCredential,
  expandBitstring,
  generateBitstring
} from "../utils"

/**
 * Generate a revocation list to store revocation status of a credential.
 *
 * @param stutusList - the existing revocation status list to use as a base
 * @param url - the revocation status list URL, which serves as the list ID
 * @param issuer - the issuer did
 * @param signer - the credential signer
 * @param issuanceDate - the creation date of this revocation list
 *
 * @returns a revocation list credential consisting of the provided status list
 */
export const generateRevocationList = async (
  statusList: number[],
  url: string,
  issuer: string,
  signer: Issuer,
  issuanceDate = new Date()
): Promise<RevocationListCredential> => {
  const encodedList = generateBitstring(statusList)

  const vcPayload: RevocationList<CredentialPayload> = {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/vc-status-list-2021/v1"
    ],
    id: url,
    type: ["VerifiableCredential", "StatusList2021Credential"],
    issuer,
    issuanceDate,
    credentialSubject: {
      id: `${url}#list`,
      type: "RevocationList2021",
      encodedList
    }
  }

  const vcJwt = await encodeVerifiableCredential(vcPayload, signer)
  return decodeVerifiableCredential(vcJwt) as Promise<RevocationListCredential>
}

/**
 * Revoke a credential in a revocation list.
 *
 * @returns a revocation list credential with the provided credential revoked
 */
export const revokeCredential = async (
  credential: RevocableCredential,
  statusList: RevocationListCredential,
  signer: Issuer
): Promise<RevocationListCredential> => {
  // If a credential does not have a credential status, it cannot be revoked.
  if (!isRevocable(credential)) {
    return statusList
  }

  const list = await expandBitstring(statusList.credentialSubject.encodedList)
  const index = parseInt(credential.credentialStatus.statusListIndex, 10)
  list.push(index)

  return await generateRevocationList(list, statusList.id, signer.did, signer)
}

/**
 * Revoke a credential in a revocation list.
 *
 * @remarks This method is safe to call on a credential that is not revocable,
 * and/or a credential that is not revoked.
 *
 * @returns a revocation list credential with the provided credential not revoked
 */
export const unrevokeCredential = async (
  credential: RevocableCredential,
  statusList: RevocationListCredential,
  signer: Issuer
): Promise<RevocationListCredential> => {
  // If a credential does not have a credential status, it cannot be revoked.
  if (!isRevocable(credential)) {
    return statusList
  }

  const list = await expandBitstring(statusList.credentialSubject.encodedList)
  const index = list.indexOf(
    parseInt(credential.credentialStatus.statusListIndex, 10)
  )
  if (index !== -1) {
    list.splice(index, 1)
  }

  return await generateRevocationList(list, statusList.id, signer.did, signer)
}

/**
 * Given a verififable credential, check if it has been revoked.
 *
 * @returns true if the credential is revoked, false otherwise
 */
export const isRevoked = async (
  credential: Verifiable<W3CCredential> | RevocableCredential,
  revocationStatusList?: RevocationListCredential
): Promise<boolean> => {
  // If there is no credentialStatus, assume not revoked
  if (!isRevocable(credential)) {
    return false
  }

  const revocableCredential = credential as RevocableCredential
  const statusList =
    revocationStatusList || (await fetchStatusList(revocableCredential))

  // This is business logic that would be left up to the Verifier. For this
  // demo, we assume if there is no revocation list or the API call fails
  // the credential is not revoked. More stringent controls may need to exist
  // for different use cases.
  if (!statusList) {
    return false
  }

  const results = await expandBitstring(
    statusList.credentialSubject.encodedList
  )

  const index = parseInt(
    (credential as RevocableCredential).credentialStatus.statusListIndex,
    10
  )

  return results.indexOf(index) !== -1
}

/**
 * Performs an HTTP request to fetch the revocation status list for a credential.
 *
 * @returns the encoded status list, if present
 */
export async function fetchStatusList(
  credential: MaybeRevocableCredential
): Promise<RevocationListCredential | undefined> {
  if (!isRevocable(credential)) {
    return
  }

  const url = (credential as RevocableCredential).credentialStatus
    .statusListCredential

  // Set 10 second timeout for fetching the revocation list.
  // For demo purposes, this is a sufficient amount of time to wait until
  // giving up. Otherwise, the verification step would continue seemingly
  // forever. Use cases beyond a demo may require different timeouts and
  // behavior.
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 10_000)
  try {
    const response = await fetch(url, { signal: controller.signal })
    clearTimeout(timeout)

    if (response.status === 200) {
      return response.json()
    }
  } catch (e) {
    // Return nothing if API call fails or timesout
  }
}

/**
 * Determine if a given credential is revocable or not.
 *
 * @returns true if the credential is revocable, false otherwise
 */
export const isRevocable = (
  credential: Verifiable<W3CCredential> | RevocableCredential
): boolean => {
  return has(credential, "credentialStatus.statusListIndex")
}
