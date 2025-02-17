import { createRoot } from 'react-dom/client'
import { Global } from '@emotion/react'
import { I18nextProvider } from 'react-i18next'
import { Provider } from 'react-redux'
import { router } from './routes/router.tsx'
import { RouterProvider } from '@tanstack/react-router'
import i18n from './locales/i18n.ts'
import store from './features/store.ts'
import styles from './styles/global.styles.ts'

console.log('Main.tsx loaded')

createRoot(document.getElementById('root')!).render(
  <Provider store={store}>
    <I18nextProvider i18n={i18n}>
      <RouterProvider router={router} />
      <Global styles={styles} />
    </I18nextProvider>
  </Provider>
)
