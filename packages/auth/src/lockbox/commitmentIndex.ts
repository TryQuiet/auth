/* eslint-disable no-bitwise, unicorn/prefer-code-point, unicorn/no-this-assignment, @typescript-eslint/no-this-alias -- Fixed-width UTF-16 radix traversal, including lone surrogate code units. */
/** Persistent radix-16 trie. Each identity character costs four fixed-width steps; appending an
 * identity never copies an N-entry map or walks a chain of earlier states. Branch/replay snapshots
 * share immutable nodes. Index values are facts about the selected lockboxes, not authorization.
 */
export class CommitmentIndex {
  private constructor(
    private readonly children: ReadonlyArray<CommitmentIndex | undefined> = [],
    private readonly value?: string
  ) {}

  static readonly empty = new CommitmentIndex()

  get(identity: string): string | undefined {
    let node: CommitmentIndex | undefined = this
    for (let offset = 0; offset < identity.length; offset++) {
      const code = identity.charCodeAt(offset)
      for (const shift of [12, 8, 4, 0]) {
        node = node.children[(code >>> shift) & 15]
        if (node === undefined) return undefined
      }
    }
    return node.value
  }

  // Preserve first-write-wins semantics for established generations.
  add(identity: string, commitment: string): CommitmentIndex {
    const path: Array<[CommitmentIndex, number]> = []
    let node: CommitmentIndex = this
    for (let offset = 0; offset < identity.length; offset++) {
      const code = identity.charCodeAt(offset)
      for (const shift of [12, 8, 4, 0]) {
        const digit = (code >>> shift) & 15
        path.push([node, digit])
        node = node.children[digit] ?? CommitmentIndex.empty
      }
    }
    if (node.value !== undefined) return this
    let replacement = new CommitmentIndex(node.children, commitment)
    for (let offset = path.length - 1; offset >= 0; offset--) {
      const [parent, digit] = path[offset]
      const children = parent.children.slice() // At most sixteen children, independent of history.
      children[digit] = replacement
      replacement = new CommitmentIndex(children, parent.value)
    }
    return replacement
  }
}
