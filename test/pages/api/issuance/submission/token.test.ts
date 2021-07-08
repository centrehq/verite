import { createMocks } from "node-mocks-http"
import { createUser } from "lib/database"
import { inssuanceManifestToken } from "lib/issuance/manifest"
import handler from "pages/api/issuance/submission/[token]"

describe("POST /issuance/submission/[token]", () => {
  it("returns a verified credential", async () => {
    const user = createUser("test@test.com", "testing")
    const token = await inssuanceManifestToken(user)

    const { req, res } = createMocks({
      method: "POST",
      query: { token, body: {} }
    })

    await handler(req, res)

    expect(res.statusCode).toBe(200)

    const response = res._getJSONData()
    expect(response.credential_fulfillment.manifest_id).toEqual(
      "Circle-KYCAMLAttestation"
    )
  })

  it("returns an error if not a POST", async () => {
    const user = createUser("test@test.com", "testing")
    const token = await inssuanceManifestToken(user)
    const { req, res } = createMocks({
      method: "GET",
      query: { token, body: {} }
    })

    await handler(req, res)

    expect(res.statusCode).toBe(405)
    expect(res._getJSONData()).toEqual({
      status: 405,
      message: "Method not allowed"
    })
  })
})