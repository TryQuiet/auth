import createBundler from '@bahmutov/cypress-esbuild-preprocessor'
import { defineConfig } from 'cypress'

export default defineConfig({
  e2e: {
    projectId: 'taco',
    baseUrl: 'http://localhost:3000',

    fixturesFolder: false,
    video: false,
    viewportWidth: 1600,
    viewportHeight: 1200,
    defaultCommandTimeout: 10000,

    setupNodeEvents(on) {
      on('file:preprocessor', createBundler())
      on('before:browser:launch', (browser = {}, launchOptions) => {
        if (browser.family === 'chromium' && browser.name !== 'electron' && browser.isHeaded) {
          // Auto-open DevTools.
          launchOptions.args.push('--auto-open-devtools-for-tabs')

          // Remove the "Chrome is being controlled" infobar.
          launchOptions.args = launchOptions.args.filter(argument => argument !== '--enable-automation')

          // Allow debugging in VS Code.
          launchOptions.args.push('--remote-debugging-port=9222')

          return launchOptions
        }

        return launchOptions
      })
    },
  },
})
