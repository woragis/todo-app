import { useSelector } from 'react-redux'
import { NavPages, Pages } from '../../types/router.types'
import { RootState } from '../../redux/store'
import { useTranslation } from 'react-i18next'
import { useAppDispatch } from '../../redux/hooks'
import { useNavigate } from 'react-router-dom'
import { logout } from '../../redux/slices/authSlice'
import { useState } from 'react'

export const useNavbarModel = () => {
  const { t } = useTranslation()
  const auth = useSelector((state: RootState) => state.auth)
  const themeColors = useSelector((state: RootState) => state.theme.colors)
  const dispatch = useAppDispatch()
  const navigate = useNavigate()
  const handleClickLogout = () => {
    dispatch(logout())
    navigate('/')
  }
  const [loginVisible, setLoginVisible] = useState<boolean>(false)
  const [registerVisible, setRegisterVisible] = useState<boolean>(false)

  const navLinks: NavPages[] = [{ title: t(Pages.Home), path: '' }]

  const unloggedLinks: NavPages[] = [
    {
      title: t('login.title'),
      path: '',
      onClick: () => {
        setLoginVisible((prevState) => !prevState)
      },
    },
    {
      title: t('register.title'),
      path: '',
      onClick: () => {
        setRegisterVisible((prevState) => !prevState)
      },
    },
  ]

  const loggedLinks: NavPages[] = [
    { title: t('profile.title'), path: Pages.Profile, onClick: () => {} },
    {
      title: t('logout.title'),
      path: '',
      onClick: () => {
        handleClickLogout()
      },
    },
  ]

  const authLinks = auth.loggedIn ? loggedLinks : unloggedLinks

  const navLogo = ''

  return {
    navLinks,
    authLinks,
    themeColors,
    navLogo,
    loginVisible,
    registerVisible,
  }
}
