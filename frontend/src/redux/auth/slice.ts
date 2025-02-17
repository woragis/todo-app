import { createSlice } from '@reduxjs/toolkit'
import { AuthState } from './types'

const authSlice = createSlice({
  name: 'auth',
  initialState: {} as AuthState,
  reducers: {},
})

export default authSlice
