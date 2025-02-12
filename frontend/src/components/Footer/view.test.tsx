import { test, expect } from 'vitest'
import { screen, render } from '@testing-library/react'
import '@testing-library/jest-dom/vitest'
import { FooterView } from './view'
import { useFooterModel } from './model'

test('Footer renders', () => {
  const model = useFooterModel()
  render(<FooterView {...model} />)

  const footer = screen.getByTestId('footer')
  expect(footer).toBeDefined
})
