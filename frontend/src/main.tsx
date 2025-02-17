import { createRoot } from 'react-dom/client'
import App from './App.tsx'
import { Provider } from 'react-redux'
import store from './redux/store.ts'
import { I18nextProvider } from 'react-i18next'
import i18n from './locales/i18n.ts'
import { RouterProvider } from '@tanstack/react-router'
import { router } from './routes/router.tsx'

console.log('Main.tsx loaded')

createRoot(document.getElementById('root')!).render(
  <Provider store={store}>
    <I18nextProvider i18n={i18n}>
      <App />
      <RouterProvider router={router} />
    </I18nextProvider>
  </Provider>
)
