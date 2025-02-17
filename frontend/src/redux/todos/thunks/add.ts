import { TodoInterface, TodoResponse, TodosState } from '../types'
import {
  ActionReducerMapBuilder,
  createAsyncThunk,
  PayloadAction,
} from '@reduxjs/toolkit'
import { TODOS_BASE_URL } from '.'
import axios from 'axios'

export const todosAddAsync = createAsyncThunk(
  'todos/add',
  async (todo: TodoInterface) => {
    const response = await axios.post<TodoResponse>(`${TODOS_BASE_URL}/`, todo)

    return response.data.data
  }
)

const addAsyncBulider = (builder: ActionReducerMapBuilder<TodosState>) => {
  builder
    .addCase(todosAddAsync.fulfilled, (state, action: PayloadAction<any>) => {
      state.loading = false
      state.error = 0
      state.todos.push(action.payload)
    })
    .addCase(todosAddAsync.pending, (state) => {
      state.loading = true
      state.error = 0
    })
    .addCase(todosAddAsync.rejected, (state) => {
      state.loading = false
      state.error = 1
    })
}

export default addAsyncBulider
