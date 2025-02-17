export interface TodoInterface {
  id: string
  title: string
  description: string
  completed: boolean
  author_id: string
}

export interface TodosState {
  todos: TodoInterface[]
  loading: boolean
  error: number
}

export interface Response {
  message: string
  status: number
  error: number
}

export interface TodosResponse extends Response {
  data: TodoInterface[]
}

export interface TodoResponse extends Response {
  data: TodoInterface
}

export interface DeleteResponse extends Response {
  data: null
}
