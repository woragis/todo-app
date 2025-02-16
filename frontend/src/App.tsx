import { Global, ThemeProvider } from '@emotion/react'
import { GlobalStyles } from './styles/global.styles'
import { useSelector } from 'react-redux'
import { RootState } from './redux/store'

function App() {
  const theme = useSelector((state: RootState) => state.theme)

  return (
    <ThemeProvider theme={theme}>
      <Global styles={GlobalStyles} />
    </ThemeProvider>
  )
}

export default App
