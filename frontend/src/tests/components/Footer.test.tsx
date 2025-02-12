import { expect, test } from 'vitest'
import { render, screen } from '../test-utils'
import '@testing-library/jest-dom'
import Footer from '../../components/Footer'

test('Renders Footer', () => {
  render(<Footer />)
  expect(screen.getByRole('contentinfo')).toBeInTheDocument()
})
