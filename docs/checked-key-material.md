# Team-owned checked key material

Each `Team` owns a private `CheckedKeyStore`. Import copies a keyset, validates
its complete shape and both public/secret keypair correspondences, computes its
commitment, and freezes the owned data. Reusing that owned record does not repeat
those checks. Only the Team's own lockbox keys are pinned for the store's lifetime;
an explicit caller-owned key argument is imported and checked on each call, is
referenced only weakly by the store, and is collectable once the caller drops it,
so explicit lookups with unrelated keysets cannot grow the store. Mutating the
original device keys cannot change the team's owned copy.

A successful lockbox opening is indexed by the complete delivery and the checked
recipient commitment. The delivery identity includes ciphertext, sender key, and
both manifests. A known contents commitment never substitutes for checking a new
delivery. Reconstructed copies of the same delivery can reuse the record across
graph replay and garbage collection. Failed openings do not create delivery records.

The current state's lockboxes determine reachability and scope/generation selection.
Retained material is not authority: a branch without a delivery or a state with
removed role access cannot select the retained key. The store retains only one
selection view, and only immutable reducer collections can reuse that view.

Material and successful delivery records live with the owning `Team`; they are
not global and are not serialized. A failed merge discards the store, including
keys opened while decrypting a valid prefix of a rejected graph. This prevents
rejected updates from accumulating retained material; the next use checks keys
again. Successful merges keep their records. Standalone selectors use a temporary store
unless given an explicit owner, and standalone `lockbox.open` returns a fresh
caller-owned copy. Existing Team key, encryption, and verification APIs and wire
formats are unchanged. Ordinary message signatures are still verified individually.

Graph-level facts are owned by the retained graph links, never by the temporary
copies `getSequence` makes: link signatures are bound to (hash, signature, resolved
public key), decrypted link bodies to (ciphertext hash, sender key, recipient key,
decryption secret) with plaintext copied on every return, and invitation/possession
proofs to (context, payload, signature, public key). Each has a bounded recent index
of `WeakRef`s (4,096 entries; 8 proof facts per owner) that only finds a fact a live
link still owns; without `WeakRef` only the owner-keyed weak maps remain. Established
commitments are indexed in an immutable radix trie extended per accepted collection.
Quiet's channel index and the separate native crypto adapter are outside this change.

## Validation

```sh
pnpm --filter @localfirst/auth... build
pnpm exec vitest run packages/auth/src packages/crdx/src packages/crypto/src packages/shared/src
```

`checkedKeyMessages.test.ts` decrypts 1,000 real role-encrypted messages without
lockbox opening, keypair validation, or key hashing after warm-up, while verifying
all 1,000 signatures and rejecting tampering. It also tests serialized graph
updates, retained removal behavior, and mutation of explicit recipient inputs.
Repeated semantic and ciphertext rejections leave graph/state unchanged and release
speculative keys; a later successful merge checks them again and retains them.
`checkedKeyStore.test.ts` covers complete delivery binding, reconstructed
collections without WeakRef, branch isolation, malformed deliveries, and ownership.

The existing Quiet `incremental-edition-bench.mjs` was also run with a separate
sender process and forced GC before each received edition at 10 and 100 users.
Both sizes required one new graph signature per edition. The first edition opened
four boxes (including initial local key import); the second opened one, with no
keypair reconstruction. This is a Linux Node 24 control, not a device benchmark.
