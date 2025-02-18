import { Action, configureStore, ThunkAction } from '@reduxjs/toolkit'
import todosSlice from './todos/slice'
import todosApi from './todos/apiSlice'
import themeSlice from './theme/slice'
import authSlice from './auth/slice'
import authApi from './auth/apiSlice'
import loginSlice from './forms/login/slice'
import registerSlice from './forms/register/slice'
import todoSlice from './forms/todo/slice'

const store = configureStore({
  reducer: {
    auth: authSlice.reducer,
    theme: themeSlice.reducer,
    todos: todosSlice.reducer,
    loginForm: loginSlice.reducer,
    registerForm: registerSlice.reducer,
    todoForm: todoSlice.reducer,
    [todosApi.reducerPath]: todosApi.reducer,
    [authApi.reducerPath]: authApi.reducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware().concat(todosApi.middleware, authApi.middleware),
})

export type AppDispatch = typeof store.dispatch
export type RootState = ReturnType<typeof store.getState>
export type AppThunk<ReturnType = void> = ThunkAction<
  ReturnType,
  RootState,
  unknown,
  Action<string>
>
export default store
