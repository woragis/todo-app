import { DeleteResponse, TodoInterface, TodosState } from '../types'
import { ActionReducerMapBuilder, PayloadAction } from '@reduxjs/toolkit'
import { createAsyncThunk } from '@reduxjs/toolkit'
import axios from 'axios'
import { TODOS_BASE_URL } from '.'

export const todosDeleteAsync = createAsyncThunk(
  'todos/delete',
  async (todo: TodoInterface) => {
    await axios.delete<DeleteResponse>(`${TODOS_BASE_URL}/${todo.id}`)

    return todo.id
  }
)

const deleteAsyncBulider = (builder: ActionReducerMapBuilder<TodosState>) => {
  builder
    .addCase(
      todosDeleteAsync.fulfilled,
      (state, action: PayloadAction<any>) => {
        state.loading = false
        state.error = 0
        state.todos = state.todos.filter((todo) => todo.id !== action.payload)
      }
    )
    .addCase(todosDeleteAsync.pending, (state) => {
      state.loading = true
      state.error = 0 // action.payload.error
    })
    .addCase(todosDeleteAsync.rejected, (state) => {
      state.loading = false
      state.error = 1 // 'Erro ao tentar deletar todo'
    })
}

export default deleteAsyncBulider
