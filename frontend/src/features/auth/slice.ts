import { createSlice, PayloadAction } from '@reduxjs/toolkit'
import { AuthResponse, AuthState } from './types'

const initialState: AuthState = { user: null, token: '', logged: false }

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    login: (state, action: PayloadAction<AuthResponse['data']>) => {
      state.user = action.payload.user
      state.token = action.payload.token
      state.logged = true
    },
    register: (state, action: PayloadAction<AuthResponse['data']>) => {
      state.user = action.payload.user
      state.token = action.payload.token
      state.logged = true
    },
    logout: (state) => {
      state = initialState
    },
  },
})

export default authSlice
