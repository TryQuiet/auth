import { TeamMetadata, type Transform } from 'team/types.js'

export const setMetadata =
  (metadata: TeamMetadata): Transform =>
  state => ({
    ...state,
    metadata: {
      ...state.metadata,
      ...metadata
    },
  })
