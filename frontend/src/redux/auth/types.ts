export interface LoginRequest {
  email: string
  password: string
}

export interface RegisterRequest extends LoginRequest {
  name: string
}

export interface UserInterface extends RegisterRequest {
  id: string
}

export interface AuthState {
  user: UserInterface
  logged: boolean
  loading: boolean
  error: number
}

export interface Response {
  message: string
  status: number
  error: number
}

export interface AuthResponse extends Response {
  data: { token: string; user: UserInterface }
}

export interface DeleteResponse extends Response {
  data: null
}
