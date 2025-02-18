import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react'
import { AuthResponse, LoginRequest, RegisterRequest } from './types'

const authApi = createApi({
  reducerPath: 'authApi',
  baseQuery: fetchBaseQuery({ baseUrl: 'http://localhost:8080/auth' }),
  tagTypes: ['auth'],
  endpoints: (builder) => ({
    login: builder.mutation<AuthResponse, LoginRequest>({
      query: (user) => ({
        url: '/login',
        body: user,
        method: 'POST',
      }),
      invalidatesTags: ['auth'],
    }),
    register: builder.mutation<AuthResponse, RegisterRequest>({
      query: (user) => ({
        url: '/register',
        body: user,
        method: 'POST',
      }),
      invalidatesTags: ['auth'],
    }),
    // putTodo: builder.mutation<TodoInterface, TodoInterface>({
    //   query: (todo) => ({
    //     url: `/${todo.id}`,
    //     body: todo,
    //     method: 'PUT',
    //   }),
    //   invalidatesTags: ['todos'],
    // }),
    // deleteTodo: builder.mutation<{}, TodoInterface['id']>({
    //   query: (id) => ({
    //     url: `/${id}`,
    //     // body: todo,
    //     method: 'DELETE',
    //   }),
    //   invalidatesTags: ['todos'],
    // }),
  }),
})

export default authApi
export const { useLoginMutation, useRegisterMutation } = authApi
