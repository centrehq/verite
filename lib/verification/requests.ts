export const kycVerificationRequest = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://identity.foundation/presentation-exchange/definition/v1"
  ],
  type: ["VerifiablePresentation", "PresentationDefinition"],
  request: {
    id: "e2556c17-b781-4490-8b0c-d31c42571c9d",
    from: "did:key:z6MktN192jgkc3RduEtC9QjWWbjdyVxTc3JHA7ouXrs6Vh6n",
    created_time: 1621438172231,
    expires_time: 2594859115000,
    reply_url: "https://id.verity.id/core/v1/presentations/response",
    reply_to: ["did:key:z6MktN192jgkc3RduEtC9QjWWbjdyVxTc3JHA7ouXrs6Vh6n"],
    callback_url: "https://f69cfb72d6c1.ngrok.io/callback",
    challenge: "e1b35ae0-9e0e-11ea-9bbf-a387b27c9e61"
  },
  presentation_definition: {
    id: "32f54163-7166-48f1-93d8-ff217bdb0653",
    input_descriptors: [
      {
        id: "kycaml_input",
        name: "Proof of KYC",
        purpose: "Please provide a valid credential from a KYC/AML issuer",
        schema: [
          {
            uri: "https://verity.id/identity/KYCAMLAttestation.json",
            required: true
          }
        ],
        constraints: {
          statuses: {
            active: {
              directive: "required"
            }
          },
          fields: [
            {
              path: ["$.issuer", "$.vc.issuer", "$.iss"],
              purpose:
                "We can only verify KYC credentials attested by a trusted authority.",
              filter: {
                type: "string",
                pattern: "did:web:verity.id|did:web:coinbase.com"
              }
            }
          ]
        }
      }
    ]
  }
}
