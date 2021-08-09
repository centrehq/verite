import {
  decodeVerificationSubmission,
  validateVerificationSubmission,
  verificationRequestWrapper
} from "@centre/verity"
import type {
  EncodedVerificationSubmission,
  VerificationRequestWrapper
} from "@centre/verity"
import { NextApiRequest } from "next"
import {
  apiHandler,
  ApiResponse,
  methodNotAllowed,
  notFound
} from "../../../../lib/api-fns"
import {
  findVerificationRequest,
  updateVerificationRequestStatus
} from "../../../../lib/database/verificationRequests"

type PostResponse = { status: string }

export default apiHandler<VerificationRequestWrapper | PostResponse>(
  async (req, res) => {
    if (req.method === "GET") {
      return get(req, res)
    }

    if (req.method === "POST") {
      return post(req, res)
    }

    return methodNotAllowed(res)
  }
)

/**
 * GET request handler
 *
 * Returns a VerificationRequest based on `id`
 */
async function get(
  req: NextApiRequest,
  res: ApiResponse<VerificationRequestWrapper>
) {
  const verificationRequest = await findVerificationRequest(
    req.query.id as string
  )

  if (!verificationRequest) {
    return notFound(res)
  }

  res.json(verificationRequestWrapper(verificationRequest))
}

/**
 * POST request handler
 *
 * Accepts and verifies a `VerificationSubmission`, and updates it's status
 */
async function post(req: NextApiRequest, res: ApiResponse<PostResponse>) {
  const submission: EncodedVerificationSubmission = req.body
  const verificationRequest = await findVerificationRequest(
    req.query.id as string
  )

  if (!verificationRequest) {
    return notFound(res)
  }

  try {
    const decoded = await decodeVerificationSubmission(submission)
    // TODO: Verify submission matches VerificationRequest (e.g. id check?)
    await validateVerificationSubmission(
      decoded,
      verificationRequest.presentation_definition
    )
  } catch (err) {
    await updateVerificationRequestStatus(
      verificationRequest.request.id,
      "rejected"
    )

    throw err
  }

  await updateVerificationRequestStatus(
    verificationRequest.request.id,
    "approved"
  )

  res.json({ status: "ok" })
}
