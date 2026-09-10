# Protocol 4: removal and rotation disabled

This Quiet release has no membership revocation or key rotation. The fixed protocol policy
disables `REMOVE_MEMBER`, `REMOVE_MEMBER_ROLE`, `REMOVE_ROLE`, `REMOVE_DEVICE`, `REMOVE_SERVER`,
`CHANGE_MEMBER_KEYS`, `CHANGE_SERVER_KEYS`, and `ROTATE_KEYS`. No graph metadata, peer request,
or runtime configuration can enable them.

Local dispatch refuses these actions. Key changes are refused before mutating the supplied
keyset. For received graphs, normal signature and authorization validation still runs; a valid
disabled action advances graph history without changing membership, devices, servers, roles,
lockboxes, or rotation requests. The resolver excludes disabled actions from concurrency rules
so a removal cannot suppress another member's valid work or an admission. Automatic deferred
rotations are also disabled, including requests from invalid-admission cleanup.

Invitations, admission, additions, role grants, and encryption remain supported. Invalid
admission cleanup still rejects identities that were never validly registered; this policy
does not turn invalid admissions into members. The existing lockbox authorization rules still
reject replacement generations smuggled onto supported actions.

Quiet deletes an entire channel through OrbitDB metadata and channel-store cleanup, without
calling auth's `REMOVE_ROLE`. `memberCanDeleteRole` therefore retains its existing admin and
role checks. `memberCanRemoveMembersFromRole` returns false. Disabling graph role removal does
not authorize ordinary members to delete channel metadata.

## Compatibility

`CONNECTION_PROTOCOL_VERSION` increases from 3 to 4. The ready message, signed identity proof,
and encrypted invitation acceptance require the current version, so an ordinary protocol 3
peer cannot synchronize using removal-enabled semantics. Quiet clients and QSS must use the
same updated auth revision. This is a breaking protocol change, independent of the application
version number.

This is **not a migration for existing protocol 3 communities**. Replaying a historical removal
under protocol 4 retains the previously removed membership. A graph containing descendants
encrypted under a now-ignored rotation may fail to load with its original keys. Providing old
rotated keys does not restore protocol 3 membership semantics. Use fresh communities or a
separately reviewed migration; this change does not supply one.

For an incoming graph whose descendant requires a disabled rotation, `Team.merge` fails during
decryption before installing any graph or state. The receiver keeps its prior keys and can
continue merging valid updates. There is no promise of interoperability with a modified peer
that continues writing under forbidden generations, or of recovering legacy rotated history.

## Test disposition

`removalRotationGate.test.ts` covers all eight action types through local APIs, correctly signed
modified-peer graphs, live merge, object load, and serialized load. It also checks concurrent
role grants, suppressed deferred rotation, an aliased caller keyset, atomic rejection of an
encrypted descendant, continued updates, invitations, private encryption, and the retained
admin channel-deletion predicate. Device admission/concurrency and malformed rotation-carrier
tests now assert the inert-removal policy. Protocol tests reject the previous version before
graph exchange and reject a protocol 3 identity signature under protocol 4.

The historical tests listed below require successful removal or rotation. They remain in the
source as explicit `it.skip` specifications for any future revocation protocol, with a policy
comment at each test. They do not establish revocation guarantees for this release. Tests for
supported signature, identity, invitation, and lockbox authorization continue to run. No test
or production switch bypasses the gate.

85 existing test cases are explicitly retired by this change:

### [connection/test/authentication.test.ts](../packages/auth/src/connection/test/authentication.test.ts)

- doesn't connect with a member who has been removed
- won't re-admit a device that was removed, even with a fresh invitation

### [connection/test/memberRoleGrant.test.ts](../packages/auth/src/connection/test/memberRoleGrant.test.ts)

- rejects a stale member grant before a non-admin peer admits the invitee
- rejects a stale grant before the server admits the invitee

### [connection/test/persistAdmission.test.ts](../packages/auth/src/connection/test/persistAdmission.test.ts)

- refuses a claim whose identity has been removed

### [connection/test/sync.test.ts](../packages/auth/src/connection/test/sync.test.ts)

- resolves concurrent duplicate removals
- lets a member remove the founder
- resolves mutual demotions in favor of the senior member
- resolves mutual removals without invalidating the senior member's concurrent actions
- gets both sides of the story in the case of mutual removals
- when a member is demoted and makes concurrent admin-only changes, discards those changes
- when a member is demoted and concurrently adds a device, the new device is kept
- when an invitation is discarded, also discard related admittance actions
- resolves circular concurrent demotions
- Alice promotes Bob then demotes him
- rotates keys after a member is removed
- rotates keys after a member is demoted
- decrypts new links received following a key rotation (upon connecting)
- allows a new member to join after team keys have been rotated
- decrypts new links received following a key rotation (while connected)
- unwinds an invalidated admission
- Eve steals Bob's phone; Bob heals the team

### [connection/test/validateInvitationAcceptance.test.ts](../packages/auth/src/connection/test/validateInvitationAcceptance.test.ts)

- rejects a fresh envelope wrapping a pre-removal graph (member)
- rejects a fresh envelope wrapping a pre-removal graph (device)
- rejects a fresh envelope wrapping a pre-removal graph sent by a server
- rejects an older-handshake admission from an active sender when id and claim both match
- rejects an admission that the membership resolver has invalidated
- rejects a graph in which the invitee was admitted and then removed

### [team/selectors/test/visibleKeys.test.ts](../packages/auth/src/team/selectors/test/visibleKeys.test.ts)

- after rotating keys, can still see the same scopes

### [team/selectors/test/visibleScopes.test.ts](../packages/auth/src/team/selectors/test/visibleScopes.test.ts)

- after rotating keys, can still see the same scopes

### [team/test/createTeam.test.ts](../packages/auth/src/team/test/createTeam.test.ts)

- deserializes a team after key rotations

### [team/test/deviceRegistration.test.ts](../packages/auth/src/team/test/deviceRegistration.test.ts)

- records when a device was admitted and when it was removed
- won't register a device id that was removed
- rejects a link signed by a device that was removed

### [team/test/devices.test.ts](../packages/auth/src/team/test/devices.test.ts)

- Bob can remove Bob's device
- Alice can remove Bob's device
- deviceWasRemoved works as expected
- throws when trying to remove a removed device
- throws when trying to access a removed device
- doesn't throw when deliberately trying to access a removed device
- has an admin rotate shared keys after a non-admin removes a device

### [team/test/duplicateAdmission.test.ts](../packages/auth/src/team/test/duplicateAdmission.test.ts)

- keeps exactly one removal tombstone and a usable member selector after merging a duplicate

### [team/test/forgedDeviceRemovalRace.test.ts](../packages/auth/src/team/test/forgedDeviceRemovalRace.test.ts)

- discards what the stolen device does while it is being removed
- does not let the stolen device lock the owner out by removing his other device first
- discards what the stolen device does when its owner is concurrently removed

### [team/test/forgedRegistration.test.ts](../packages/auth/src/team/test/forgedRegistration.test.ts)

- rejects registering a device id that was removed
- rejects a device admitted against an invitation whose owner has left the team

### [team/test/forgedRemoval.test.ts](../packages/auth/src/team/test/forgedRemoval.test.ts)

- rejects links signed by a removed member’s device
- rejects links signed by a removed member’s device even when the device itself was left alone

### [team/test/invitationRoleGrant.test.ts](../packages/auth/src/team/test/invitationRoleGrant.test.ts)

- rejects a stale grant before assigning the role

### [team/test/keys.test.ts](../packages/auth/src/team/test/keys.test.ts)

- after changing his keys, Bob still has team keys
- has an admin rotate shared keys after a non-admin changes their USER keys
- Every time Alice changes her keys, the admin keys are rotated

### [team/test/keysetCommitmentAuthorization.test.ts](../packages/auth/src/team/test/keysetCommitmentAuthorization.test.ts)

- drops a conflicting historical-generation redistribution

### [team/test/lockboxAuthorizationHardening.test.ts](../packages/auth/src/team/test/lockboxAuthorizationHardening.test.ts)

- does not carry a retired generic recipient into a subsequent role rotation
- does not let an unrelated member pre-seed a future USER generation
- selects the legitimate USER key change in both concurrent merge orders
- does not let an unrelated member pre-seed a future SERVER generation
- preserves an authenticated ROTATE_KEYS recipient transition

### [team/test/lockboxChannelTakeover.test.ts](../packages/auth/src/team/test/lockboxChannelTakeover.test.ts)

- still lets an admin rotate the team key when removing a member
- still lets an admin rotate the channel key when removing a member from it

### [team/test/lockboxPostRotationAdmission.test.ts](../packages/auth/src/team/test/lockboxPostRotationAdmission.test.ts)

- lockboxes every team-key generation to the joiner

### [team/test/lockboxRotationConcurrency.test.ts](../packages/auth/src/team/test/lockboxRotationConcurrency.test.ts)

- does not poison the graph when a role add lands before a concurrent re-key

### [team/test/members.test.ts](../packages/auth/src/team/test/members.test.ts)

- removes a member
- only admins can remove members
- rotates keys after removing a member
- doesn't do anything if asked to remove a nonexistent member

### [team/test/membershipResolver.test.ts](../packages/auth/src/team/test/membershipResolver.test.ts)

- discards changes made by a member who is concurrently removed
- discards changes made by a member who is concurrently demoted
- resolves mutual concurrent removals in favor of the team founder
- resolves mutual concurrent removals in favor of the senior member
- resolves mutual concurrent demotions in favor of the team founder
- resolves circular mutual concurrent demotions in favor of the team founder

### [team/test/roles.test.ts](../packages/auth/src/team/test/roles.test.ts)

- removes a member from a role
- removes a role
- Alice can remove herself as admin as long as there at least one other admin
- rotates keys when a member is removed from a role

### [team/test/sameGenerationLockboxReplacement.test.ts](../packages/auth/src/team/test/sameGenerationLockboxReplacement.test.ts)

- a removed role member cannot rebind the current generation to a key they control
- nor by lying in the manifest about which key the lockbox contains

### [team/test/securityCandidates.poc.test.ts](../packages/auth/src/team/test/securityCandidates.poc.test.ts)

- does not deliver the replacement role key to the principal removed by the rotation
- does not deliver replacement USER or TEAM keys to a fully removed member
- can leave the target of a losing concurrent member removal with the winning team key
- can fail to recover a descendant written under a losing concurrent team rotation

### [team/test/servers.test.ts](../packages/auth/src/team/test/servers.test.ts)

- can't be re-added after being removed
- has its keys rotated by an admin
