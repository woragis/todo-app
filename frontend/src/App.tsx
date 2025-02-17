import { Global, ThemeProvider } from '@emotion/react'
import { GlobalStyles } from './styles/global.styles'
import { useAppSelector } from './features/hooks'

function App() {
  const theme = useAppSelector((state) => state.theme.colors)

  return (
    <ThemeProvider theme={theme}>
      <Global styles={GlobalStyles} />
    </ThemeProvider>
  )
}

export default App
