import { NextApiHandler } from "next"
import { notFound } from "lib/api-fns"
import { MANIFEST_MAP } from "lib/issuance/manifest"
import { CredentialManifest } from "lib/verity"

const handler: NextApiHandler<CredentialManifest> = async (req, res) => {
  const manifest = MANIFEST_MAP[req.query.type as string]

  if (!manifest) {
    return notFound(res)
  }

  res.json(manifest)
}

export default handler
