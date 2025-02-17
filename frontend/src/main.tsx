import { createRoot } from 'react-dom/client'
import { I18nextProvider } from 'react-i18next'
import { Provider } from 'react-redux'
import { router } from './routes/router.tsx'
import { RouterProvider } from '@tanstack/react-router'
import App from './App.tsx'
import i18n from './locales/i18n.ts'
import store from './features/store.ts'

console.log('Main.tsx loaded')

createRoot(document.getElementById('root')!).render(
  <Provider store={store}>
    <I18nextProvider i18n={i18n}>
      <App />
      <RouterProvider router={router} />
    </I18nextProvider>
  </Provider>
)
