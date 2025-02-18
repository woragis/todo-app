import { createSlice, PayloadAction } from '@reduxjs/toolkit'
import { TodoBody } from './types'

const initialState: TodoBody = { title: '', description: '' }

const todoSlice = createSlice({
  name: 'todo-form',
  initialState,
  reducers: {
    set: (state, action: PayloadAction<TodoBody>) => {
      state.title = action.payload.title
      state.description = action.payload.description
    },
    reset: (state) => {
      state = initialState
    },
  },
})

export default todoSlice
