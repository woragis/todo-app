import { createRoot } from 'react-dom/client'
import App from './App.tsx'
import { Provider } from 'react-redux'
import { store } from './redux/store.ts'
import { I18nextProvider } from 'react-i18next'
import i18n from './locales/i18n.ts'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

const client = new QueryClient()

createRoot(document.getElementById('root')!).render(
  <QueryClientProvider client={client}>
    <Provider store={store}>
      <I18nextProvider i18n={i18n}>
        <App />
      </I18nextProvider>
    </Provider>
  </QueryClientProvider>
)
