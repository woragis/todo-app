import { expect, test } from 'vitest'
import { render, screen } from '../test-utils'
import '@testing-library/jest-dom'
import ThemeButton from '../../components/ThemeButton'

test('Renders Footer', () => {
  render(
    <ThemeButton
      navbarColor='#fff'
      navbarBackgroundColor='#000'
    />
  )
  expect(screen.getByRole('button')).toBeInTheDocument()
})
