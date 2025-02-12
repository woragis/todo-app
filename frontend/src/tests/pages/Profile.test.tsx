import { describe, expect, test } from 'vitest'
import { render, screen } from '../test-utils'
import '@testing-library/jest-dom'
import Profile from '../../pages/Profile'

describe('Test Home', () => {
  test('Test Links', () => {
    render(<Profile />)
    // expect(screen.getByText('Profile')).toBeInTheDocument()
  })
})
