import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react'
import { AuthResponse, LoginRequest, RegisterRequest } from './types'
import { auth } from './actions'

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
      async onQueryStarted(_, { dispatch, queryFulfilled }) {
        try {
          const { data } = await queryFulfilled
          dispatch(auth(data.data))
        } catch (err) {
          console.error('Login error: ', err)
        }
      },
    }),
    register: builder.mutation<AuthResponse, RegisterRequest>({
      query: (user) => ({
        url: '/register',
        body: user,
        method: 'POST',
      }),
      async onQueryStarted(_, { dispatch, queryFulfilled }) {
        try {
          const { data } = await queryFulfilled
          dispatch(auth(data.data))
        } catch (err) {
          console.error('Login error: ', err)
        }
      },
    }),
  }),
})

export default authApi
export const { useLoginMutation, useRegisterMutation } = authApi
