import dark from '@/styles/themes/dark'

export interface ThemeSliceInterface {
  mode: 'dark' | 'light' | 'automatic'
  colors: typeof dark
}
