import { createSlice } from "@reduxjs/toolkit";
import dark from "../../styles/themes/dark";
import light from "../../styles/themes/light";

interface ThemeSliceInterface {
  isDarkMode: boolean;
  colors: typeof dark;
}

const initialState: ThemeSliceInterface = {
  isDarkMode: true,
  colors: dark,
};

const themeSlice = createSlice({
  name: "theme",
  initialState,
  reducers: {
    toggleTheme: (state) => {
      state.isDarkMode = !state.isDarkMode;
      state.colors = state.isDarkMode ? light : dark;
    },
    setLightTheme: (state) => {
      state.isDarkMode = false;
      state.colors = light;
    },
    setDarkTheme: (state) => {
      state.isDarkMode = true;
      state.colors = dark;
    },
  },
});

export const { toggleTheme, setLightTheme, setDarkTheme } = themeSlice.actions;
export default themeSlice.reducer;
