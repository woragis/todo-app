import { TodosResponseInterface } from './axios.types'
import { ReduxStatus } from './redux.types'

export interface Todo {
  id: number
  name: string
  description: string
  author_id: string
  created_at: string
}

export interface TodosState {
  data: TodosResponseInterface['data']
  currentTodo: Todo | undefined
  status: ReduxStatus
  error: string | null
}

export interface PostTodoRequest {
  name: Todo['name']
  author_id: Todo['author_id']
}

export interface PutTodoRequest extends PostTodoRequest {
  id: Todo['id']
}
