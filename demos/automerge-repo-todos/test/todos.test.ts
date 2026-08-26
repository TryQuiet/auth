import { BrowserContext, expect, Locator, test } from '@playwright/test'
import { newBrowser } from './helpers/App'

const TODOS = ['buy some cheese', 'feed the cat', 'book a doctors appointment']

const expectBothTodos = async (todos: Locator) => {
  await expect(todos).toHaveCount(2)
  const values = await todos.evaluateAll(inputs => inputs.map(input => (input as HTMLInputElement).value))
  expect(values).toEqual(expect.arrayContaining(TODOS.slice(0, 2)))
}

const setup = async (context: BrowserContext) => {
  const alice = await newBrowser(context)
  await alice.createTeam('Alice', 'Alice & friends')
  await alice.expect.toBeLoggedIn('Alice')
  // Alice invites Bob
  const invitationCode = await alice.createMemberInvitation()

  // Bob joins
  const bob = await newBrowser(context)
  await bob.joinAsMember('Bob', invitationCode)
  await bob.expect.toBeLoggedIn('Bob')

  // Alice and Bob add one todo each
  await alice.addTodo(TODOS[0])
  await bob.addTodo(TODOS[1])

  return { alice, bob }
}

test('syncs todos between two members', async ({ context }) => {
  const { alice, bob } = await setup(context)
  // Concurrent Automerge insertions can arrive in either order.
  await expectBothTodos(alice.todos())
  await expectBothTodos(bob.todos())
})

test('syncs checked state', async ({ context }) => {
  const { alice, bob } = await setup(context)

  // Alice checks her todo.
  await alice.toggleTodo(TODOS[0])

  // Alice sees her todo checked.
  await expect(alice.todoCheckbox(TODOS[0])).toBeChecked()
  await expect(alice.todoCheckbox(TODOS[1])).not.toBeChecked()

  // Bob sees Alice's todo checked.
  await expect(bob.todoCheckbox(TODOS[0])).toBeChecked()
  await expect(bob.todoCheckbox(TODOS[1])).not.toBeChecked()

  // Bob checks his todo.
  await bob.toggleTodo(TODOS[1])

  // Alice sees both todos checked.
  await expect(alice.todoCheckbox(TODOS[0])).toBeChecked()
  await expect(alice.todoCheckbox(TODOS[1])).toBeChecked()

  // Bob sees both todos checked.
  await expect(bob.todoCheckbox(TODOS[0])).toBeChecked()
  await expect(bob.todoCheckbox(TODOS[1])).toBeChecked()

  // Alice unchecks her todo.
  await alice.toggleTodo(TODOS[0])

  // Alice sees only Bob's todo checked.
  await expect(alice.todoCheckbox(TODOS[0])).not.toBeChecked()
  await expect(alice.todoCheckbox(TODOS[1])).toBeChecked()

  // Bob sees only his todo checked.
  await expect(bob.todoCheckbox(TODOS[0])).not.toBeChecked()
  await expect(bob.todoCheckbox(TODOS[1])).toBeChecked()
})

test('syncs todos between two devices', async ({ context }) => {
  const laptop = await newBrowser(context)
  await laptop.createTeam('Alice', 'Alice & friends')
  await laptop.expect.toBeLoggedIn('Alice')

  // Alice creates a device invitation
  const invitationCode = await laptop.createDeviceInvitation()

  // She enters the code on her phone
  const phone = await newBrowser(context)
  await phone.joinAsDevice('Alice', invitationCode)
  await phone.expect.toBeLoggedIn('Alice')

  // each device adds a todo
  await laptop.addTodo(TODOS[0])
  await phone.addTodo(TODOS[1])

  // Concurrent Automerge insertions can arrive in either order.
  await expectBothTodos(laptop.todos())
  await expectBothTodos(phone.todos())
})
