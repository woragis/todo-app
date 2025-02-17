import { useSelector } from 'react-redux'
import { RootState } from '../../redux_old/store'
import { useTranslation } from 'react-i18next'

export const useProfileModel = () => {
  const { t } = useTranslation()
  const user = useSelector((state: RootState) => state.auth.user)

  const textData = {
    title: t('profile.title'),
    nameField: t('profile.user-fields.name'),
    emailField: t('profile.user-fields.email'),
    passwordField: t('profile.user-fields.password'),
    createdField: t('profile.user-fields.created-at'),
    updatedField: t('profile.user-fields.updated-at'),
  }
  return { textData, user }
}
