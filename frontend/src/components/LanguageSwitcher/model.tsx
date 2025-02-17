import { useAppSelector } from '@/redux/hooks'
import { useTranslation } from 'react-i18next'

export const useLanguageSwitcherModel = () => {
  const { i18n, t } = useTranslation()
  const changeLanguage = (lang: string) => {
    i18n.changeLanguage(lang)
  }
  const languages = [
    { code: 'en', label: 'English' },
    { code: 'es', label: 'Espanhol' },
    { code: 'pt', label: 'Portugues' },
  ]

  const themeColors = useAppSelector((state) => state.theme.colors)

  return { t, changeLanguage, languages, themeColors }
}
