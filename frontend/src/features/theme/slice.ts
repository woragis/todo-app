import { createSlice } from '@reduxjs/toolkit'
import dark from '../../styles/themes/dark'
import light from '../../styles/themes/light'
import { ThemeSliceInterface } from './types'

const initialState: ThemeSliceInterface = {
  mode: 'automatic',
  colors: dark,
}

const themeSlice = createSlice({
  name: 'theme',
  initialState,
  reducers: {
    toggleTheme: (state) => {
      state.mode = state.mode === 'dark' ? 'light' : 'dark'
      state.colors = state.mode === 'dark' ? light : dark
    },
    setLightTheme: (state) => {
      state.mode = 'light'
      state.colors = light
    },
    setDarkTheme: (state) => {
      state.mode = 'dark'
      state.colors = dark
    },
  },
})

export const { toggleTheme, setLightTheme, setDarkTheme } = themeSlice.actions
export default themeSlice
