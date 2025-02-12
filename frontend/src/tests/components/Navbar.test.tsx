import { expect, test } from 'vitest'
import { render, screen } from '../test-utils'
import '@testing-library/jest-dom'
import Navbar from '../../components/Navbar'

test('Renders Footer', () => {
  render(<Navbar />)
  expect(screen.getByRole('navigation')).toBeInTheDocument()
})
