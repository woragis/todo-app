import { ChangeEvent, FormEvent, useState } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { useTranslation } from 'react-i18next'
import { LoginRequestInterface } from '../../types/axios.types'
import { useAppDispatch, useAppSelector } from '@/features/hooks'
import { useLoginMutation } from '@/features/auth/apiSlice'
import { login } from '@/features/auth/actions'

export const useLoginModel = () => {
  const { t } = useTranslation()
  const dispatch = useAppDispatch()
  const navigate = useNavigate()
  const { logged } = useAppSelector((state) => state.auth)

  const [loginData, setLoginData] = useState<LoginRequestInterface>({
    email: '',
    password: '',
  })

  const handleLoginChange = (event: ChangeEvent<HTMLInputElement>) => {
    setLoginData(
      (prevState) =>
        (prevState = { ...prevState, [event.target.name]: event.target.value })
    )
  }

  const [loginMutation, { isLoading }] = useLoginMutation()

  const handleLoginSubmit = async (event: FormEvent) => {
    event.preventDefault()
    const responseUser = await (await loginMutation(loginData).unwrap()).data
    dispatch(login(responseUser))
    navigate({ to: '/profile' })
  }

  const textData = {
    title: t('login.title'),
    emailInput: t('login.inputs.email'),
    passwordInput: t('login.inputs.password'),
    formButton: t('login.inputs.button'),
  }

  return {
    textData,
    logged,
    loginData,
    handleLoginChange,
    handleLoginSubmit,
    isLoading,
  }
}
