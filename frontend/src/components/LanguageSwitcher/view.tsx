import { useLanguageSwitcherModel } from './model'
import {
  LanguageButton,
  LanguageOptionsContainer,
  OptionsContainer,
  StyledLanguageOption,
} from './styles'

export const LanguageSwitcherView = ({
  t,
  changeLanguage,
  languages,
  themeColors,
}: ReturnType<typeof useLanguageSwitcherModel>) => {
  const languagesComponent = languages.map(({ code, label }) => {
    return (
      <StyledLanguageOption
        key={code + '_language_button'}
        onClick={() => changeLanguage(code)}
      >
        {label}
      </StyledLanguageOption>
    )
  })
  return (
    <LanguageOptionsContainer
      color={themeColors.secondary.dark}
      backgroundColor={themeColors.background.contrast}
    >
      <LanguageButton>{t('changeLanguage')}</LanguageButton>
      <OptionsContainer>{languagesComponent}</OptionsContainer>
    </LanguageOptionsContainer>
  )
}
