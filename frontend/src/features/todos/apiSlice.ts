import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react'
import { TodoInterface, TodosResponse } from './types'

const todosApi = createApi({
  reducerPath: 'todosApi',
  baseQuery: fetchBaseQuery({ baseUrl: 'http://localhost:8080/todos' }),
  tagTypes: ['todos'],
  endpoints: (builder) => ({
    getTodos: builder.query<TodoInterface[], void>({
      query: () => '',
      providesTags: ['todos'],
      transformResponse: (response: TodosResponse) => {
        return response.data
      },
    }),
    getTodoById: builder.query<TodoInterface, TodoInterface['id']>({
      query: (id) => `/${id}`,
      providesTags: ['todos'],
    }),
    postTodo: builder.mutation<TodoInterface, TodoInterface>({
      query: (todo) => ({
        url: '/',
        body: todo,
        method: 'POST',
      }),
      invalidatesTags: ['todos'],
    }),
    putTodo: builder.mutation<TodoInterface, TodoInterface>({
      query: (todo) => ({
        url: `/${todo.id}`,
        body: todo,
        method: 'PUT',
      }),
      invalidatesTags: ['todos'],
    }),
    deleteTodo: builder.mutation<{}, TodoInterface['id']>({
      query: (id) => ({
        url: `/${id}`,
        // body: todo,
        method: 'DELETE',
      }),
      invalidatesTags: ['todos'],
    }),
  }),
})

export default todosApi
export const {
  useGetTodosQuery,
  useGetTodoByIdQuery,
  usePostTodoMutation,
  usePutTodoMutation,
  useDeleteTodoMutation,
} = todosApi
