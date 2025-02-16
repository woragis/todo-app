import { describe, expect, test } from 'vitest'
import { render, screen } from '../test-utils'
import '@testing-library/jest-dom'
import { TodoView } from '../../pages/Todo/view'
import { Todo as TodoType } from '../../types/todos.types'

describe('TodoView Component', () => {
  test('renders "Did not find todo" when todo is undefined', () => {
    render(<TodoView todo={undefined} />)

    expect(screen.getByText(/Did not find todo/i)).toBeInTheDocument()
  })

  test('renders todo details when provided', () => {
    const mockTodo: TodoType = {
      id: '1',
      name: 'Test Todo',
      description: 'This is a test todo',
      author_id: '2',
      created_at: '',
    }

    render(<TodoView todo={mockTodo} />)

    expect(screen.getByText(/id: 1/i)).toBeInTheDocument()
    expect(screen.getByText(/Title: Test Todo/i)).toBeInTheDocument()
    expect(screen.getByText(/This is a test todo/i)).toBeInTheDocument()
  })
})
