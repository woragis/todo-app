import { createAsyncThunk } from '@reduxjs/toolkit'
import { TODOS_BASE_URL } from '.'
import { ActionReducerMapBuilder, PayloadAction } from '@reduxjs/toolkit'
import axios from 'axios'
import { TodosResponse, TodosState } from '../types'

export const todosFetchAsync = createAsyncThunk('todos/fetch', async () => {
  const response = await axios.get<TodosResponse>(`${TODOS_BASE_URL}/`)

  return response.data.data
})

const fetchAsyncBulider = (builder: ActionReducerMapBuilder<TodosState>) => {
  builder
    .addCase(todosFetchAsync.fulfilled, (state, action: PayloadAction<any>) => {
      state.loading = false
      state.error = 0
      state.todos = action.payload
    })
    .addCase(todosFetchAsync.pending, (state) => {
      state.loading = true
      state.error = 0
    })
    .addCase(todosFetchAsync.rejected, (state) => {
      state.loading = false
      state.error = 1 // 'Erro ao tentar achar todos'
    })
}

export default fetchAsyncBulider
