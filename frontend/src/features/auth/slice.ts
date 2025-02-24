import { createSlice, PayloadAction } from '@reduxjs/toolkit'
import { AuthResponse, AuthState, UserInterface } from './types'
import Cookies from 'js-cookie'

const get = () => {
  let token = Cookies.get('token') || ''
  let userCookie = Cookies.get('user')
  let user = JSON.parse(userCookie || '{}') as UserInterface
  let logged = token.length > 0
  return { user, token, logged }
}

const initialState: AuthState = get()

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    auth: (state, action: PayloadAction<AuthResponse['data']>) => {
      state.user = action.payload.user
      state.token = action.payload.token
      Cookies.set('user', JSON.stringify(action.payload.user))
      Cookies.set('token', action.payload.token)
      state.logged = true
    },
    logout: (state) => {
      Cookies.remove('user')
      Cookies.remove('token')
      state = initialState
    },
  },
})

export default authSlice
