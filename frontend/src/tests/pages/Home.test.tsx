import { describe, test } from 'vitest'
import { render } from '../test-utils'
import '@testing-library/jest-dom'
// import Home from '../../pages/Home'
import { HomeView } from '../../pages/Home/view'
import { useHomeModel } from '../../pages/Home/model'
import { TodosResponseInterface } from '../../types/axios.types'

describe('Test Home', () => {
  test('Test Links', () => {
    const homeProps: ReturnType<typeof useHomeModel> = {
      dividerColor: '#000',
      todosTitle: 'Todos',
      todosNotFound: 'Not found',
      todos: {
        isLoading: false,
        error: null,
        data: {} as TodosResponseInterface,
      },
    }

    render(<HomeView {...homeProps} />)
    // expect(screen.getByText('Todos')).toBeInTheDocument()
  })
})
