import { expect } from 'vitest'
import { type ValidationResult } from 'validator/index.js'

// ignore coverage
expect.extend({
  toBeValid(validation: ValidationResult, expectedMessage?: string) {
    if (validation.isValid)
      return {
        message: () => 'expected validation not to pass',
        pass: true,
      }

    if (expectedMessage && (validation.error == null || !new RegExp(expectedMessage).test(validation.error.message)))
      return {
        message: () =>
          `expected validation to fail with message ${expectedMessage}, but got ${validation.error.message}`,
        pass: true,
      }
    return {
      message: () => validation.error?.message ?? 'expected validation to pass',
      pass: false,
    }
  },
})
