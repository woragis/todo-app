import { Action, configureStore, ThunkAction } from '@reduxjs/toolkit'
import todosSlice from './todos/slice'
import todosApi from './todos/apiSlice'
import themeSlice from './theme/slice'

const store = configureStore({
  reducer: {
    theme: themeSlice.reducer,
    todos: todosSlice.reducer,
    [todosApi.reducerPath]: todosApi.reducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware().concat(todosApi.middleware),
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
