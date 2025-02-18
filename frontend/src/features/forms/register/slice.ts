import { createSlice, PayloadAction } from '@reduxjs/toolkit'
import { RegisterBody } from './types'

const initialState: RegisterBody = { name: '', email: '', password: '' }

const registerSlice = createSlice({
  name: 'register-form',
  initialState,
  reducers: {
    set: (state, action: PayloadAction<RegisterBody>) => {
      state.name = action.payload.name
      state.email = action.payload.email
      state.password = action.payload.password
    },
    reset: (state) => {
      state = initialState
    },
  },
})

export default registerSlice
