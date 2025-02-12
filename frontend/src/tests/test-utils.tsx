import { render } from '@testing-library/react'
import '@testing-library/react'
import { Provider } from 'react-redux'
import { store } from '../redux/store'
import { I18nextProvider } from 'react-i18next'
import i18n from '../locales/i18n'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'
import { ThemeProvider } from '@emotion/react'
import { GlobalStyles } from '../styles/global.styles'
import { Global } from '@emotion/react'
import { RootState } from '../redux/store'
import { useSelector } from 'react-redux'
import light from '../styles/themes/light'
import dark from '../styles/themes/dark'

const queryClient = new QueryClient()

// ✅ This component wraps everything inside the necessary providers
const AppWrapper = ({ children }: { children: React.ReactNode }) => {
  //   const theme = useSelector((state: RootState) => state.theme)
  const theme = dark

  return (
    <QueryClientProvider client={queryClient}>
      <Provider store={store}>
        <I18nextProvider i18n={i18n}>
          <BrowserRouter>
            <ThemeProvider theme={theme}>
              <Global styles={GlobalStyles} />
              {children}
            </ThemeProvider>
          </BrowserRouter>
        </I18nextProvider>
      </Provider>
    </QueryClientProvider>
  )
}

// ✅ Custom render function to use in all tests
const customRender = (ui: React.ReactElement, options = {}) =>
  render(<AppWrapper>{ui}</AppWrapper>, options)

export * from '@testing-library/react'
export { customRender as render }
