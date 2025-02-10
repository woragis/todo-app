import { configureStore } from "@reduxjs/toolkit";
import authReducer from "./slices/authSlice";
import todosReducer from "./slices/todosSlice";
import themeReducer from "./slices/themeSlice";

export const store = configureStore({
  reducer: {
    auth: authReducer,
    theme: themeReducer,
    todos: todosReducer,
  },
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
