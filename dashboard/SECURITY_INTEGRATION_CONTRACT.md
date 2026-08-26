# Future Stage 2D Integration Contract

This document is a product-side interface placeholder, not authorization to modify Stage 2D.

The final dashboard-to-local-service relationship must preserve these properties:

1. Dashboard/browser is untrusted and can create drafts only.
2. Production key generation and custody occur only in the trusted local service.
3. Approval is bound to an immutable request/canonical payload and is performed in trusted local UI/state.
4. Technocore signed-room payload uses the reviewed canonical normalization contract before signing.
5. Nonce state is persistent and strictly increasing per DID/room; wall-clock milliseconds are not authoritative nonce state.
6. CORS/origin allowlists are supplemental browser policy, not authentication.
7. No private-key export endpoint is exposed to the browser/cloud.
8. Public UI must not claim offline signature re-verification unless the actual signature bytes and verification path are present and executed.
9. Persistent indexing must expose gaps/coverage rather than imply complete Technocore history.
10. Integration is a later explicit gate after security-core freeze; this prototype must not reach into frozen Stage 2D internals now.
