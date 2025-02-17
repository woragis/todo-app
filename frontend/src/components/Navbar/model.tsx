import { NavPages, Pages } from '../../types/router.types'
import { useTranslation } from 'react-i18next'
import { useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import { useAppDispatch, useAppSelector } from '@/features/hooks'

export const useNavbarModel = () => {
  const { t } = useTranslation()
  const auth = useAppSelector((state) => state.auth)
  const themeColors = useAppSelector((state) => state.theme.colors)
  const dispatch = useAppDispatch()
  const navigate = useNavigate()
  const handleClickLogout = () => {
    // dispatch(logout())
    navigate({
      to: '/',
    })
  }

  const navLinks: NavPages[] = [{ title: t(Pages.Home), path: '' }]

  const unloggedLinks: NavPages[] = [
    {
      title: t('login.title'),
      path: 'auth/login',
      onClick: () => {},
    },
    {
      title: t('register.title'),
      path: 'auth/register',
      onClick: () => {},
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

  const authLinks = auth.logged ? loggedLinks : unloggedLinks

  const navLogo = ''

  return {
    navLinks,
    authLinks,
    themeColors,
    navLogo,
  }
}
