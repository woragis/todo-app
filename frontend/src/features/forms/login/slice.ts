import { createSlice, PayloadAction } from '@reduxjs/toolkit'
import { LoginBody } from './types'

const initialState: LoginBody = { email: '', password: '' }

const loginSlice = createSlice({
  name: 'login-form',
  initialState,
  reducers: {
    set: (state, action: PayloadAction<LoginBody>) => {
      state.email = action.payload.email
      state.password = action.payload.password
    },
    reset: (state) => {
      state = initialState
    },
  },
})

export default loginSlice
