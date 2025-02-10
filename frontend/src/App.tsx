import { BrowserRouter } from 'react-router-dom'
import AppRouter from './pages/router'
import { Global, ThemeProvider } from '@emotion/react'
import { GlobalStyles } from './styles/global.styles'
import { useSelector } from 'react-redux'
import { RootState } from './redux/store'

function App() {
  const theme = useSelector((state: RootState) => state.theme)

  return (
    <BrowserRouter>
      <ThemeProvider theme={theme}>
        <Global styles={GlobalStyles} />
        <AppRouter />
      </ThemeProvider>
    </BrowserRouter>
  )
}

export default App
