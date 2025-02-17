import { createSlice, PayloadAction } from '@reduxjs/toolkit'
import {
  addAsyncBulider,
  editAsyncBulider,
  deleteAsyncBulider,
  fetchAsyncBulider,
} from './thunks'
import { TodoInterface, TodosState } from './types'

export const todosSlice = createSlice({
  name: 'todos',
  initialState: { todos: [] as TodoInterface[] } as TodosState,
  reducers: {
    addTodo: (state, action: PayloadAction<TodoInterface>) => {
      state.todos.push(action.payload)
    },
    editTodo: (state, action: PayloadAction<TodoInterface>) => {
      state.todos = state.todos.map((todo) => {
        if (todo.id === action.payload.id) {
          return { ...todo, title: action.payload.title }
        }
        return todo
      })
    },
    deleteTodo: (state, action: PayloadAction<TodoInterface>) => {
      state.todos = state.todos.filter((todo) => todo.id !== action.payload.id)
    },
  },
  extraReducers: (builder) => {
    fetchAsyncBulider(builder)
    addAsyncBulider(builder)
    editAsyncBulider(builder)
    deleteAsyncBulider(builder)
  },
})

export default todosSlice
