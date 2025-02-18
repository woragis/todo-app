import { createSlice, PayloadAction } from '@reduxjs/toolkit'
import { AuthResponse, AuthState } from './types'

const authSlice = createSlice({
  name: 'auth',
  initialState: {} as AuthState,
  reducers: {
    login: (state, action: PayloadAction<AuthResponse['data']>) => {
      state.user = action.payload.user
      state.token = action.payload.token
    },
    register: (state, action: PayloadAction<AuthResponse['data']>) => {
      state.user = action.payload.user
      state.token = action.payload.token
    },
  },
})

export default authSlice
