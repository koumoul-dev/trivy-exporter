import neostandard from 'neostandard'

export default [
  ...neostandard({ ts: true, noJsx: true }),
  {
    rules: {
      'no-undef': 'off' // taken care of by typescript
    }
  }
]
