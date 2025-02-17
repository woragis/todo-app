import { TodoResponse, TodoInterface, TodosState } from '../types'
import {
  ActionReducerMapBuilder,
  createAsyncThunk,
  PayloadAction,
} from '@reduxjs/toolkit'
import { TODOS_BASE_URL } from '.'
import axios from 'axios'

export const todosEditAsync = createAsyncThunk(
  'todos/edit',
  async (todo: TodoInterface) => {
    const response = await axios.put<TodoResponse>(
      `${TODOS_BASE_URL}/${todo.id}`,
      todo
    )

    return response.data.data
  }
)

const editAsyncBulider = (builder: ActionReducerMapBuilder<TodosState>) => {
  builder
    .addCase(todosEditAsync.fulfilled, (state, action: PayloadAction<any>) => {
      state.loading = false
      state.error = 0
      state.todos = state.todos.map((todo) => {
        if (todo.id === action.payload.id) {
          return { ...todo, title: action.payload.title }
        }
        return todo
      })
    })
    .addCase(todosEditAsync.pending, (state) => {
      state.loading = true
      state.error = 0
    })
    .addCase(todosEditAsync.rejected, (state) => {
      state.loading = false
      state.error = 1 // 'Erro ao adicionar Todo'
    })
}

export default editAsyncBulider
