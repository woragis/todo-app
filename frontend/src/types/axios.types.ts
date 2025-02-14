import { AuthUser } from './auth.types'
import { Todo } from './todos.types'

export interface API_ENDPOINTS_INTERFACE {
  USERS: string
  POSTS: string
  AUTH: {
    LOGIN: string
    REGISTER: string
    RECOVER_PASSWORD: string
    VERIFY: string
  }
}

export interface ResponseInterface {
  status: number
  message: string
  error: null | string
}

export interface AuthResponseInterface extends ResponseInterface {
  data: {
    user: AuthUser
    token: string
  }
}

export interface LoginRequestInterface {
  email: AuthUser['email']
  password: AuthUser['password']
}

export interface RegisterRequestInterface extends LoginRequestInterface {
  name: AuthUser['name']
}

export interface TodosResponseInterface extends ResponseInterface {
  data: Todo[]
}

export interface TodoResponseInterface extends ResponseInterface {
  data: Todo
}

export interface DeleteTodoResponseInterface extends ResponseInterface {
  data: boolean
}
