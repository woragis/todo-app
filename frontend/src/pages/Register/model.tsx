import { ChangeEvent, FormEvent, useState } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { useTranslation } from 'react-i18next'
import { RegisterRequestInterface } from '../../types/axios.types'
import { useAppDispatch, useAppSelector } from '@/features/hooks'
import { register } from '@/features/auth/actions'
import { useRegisterMutation } from '@/features/auth/apiSlice'

export const useRegisterModel = () => {
  const { t } = useTranslation()
  const dispatch = useAppDispatch()
  const navigate = useNavigate()
  const { logged } = useAppSelector((state) => state.auth)

  const [registerData, setRegisterData] = useState<RegisterRequestInterface>({
    name: '',
    email: '',
    password: '',
  })

  const [registerMutation, { isLoading }] = useRegisterMutation()

  const handleRegisterChange = (event: ChangeEvent<HTMLInputElement>) => {
    setRegisterData((prevState) => ({
      ...prevState,
      [event.target.name]: event.target.value,
    }))
  }

  const handleRegisterSubmit = async (event: FormEvent) => {
    event.preventDefault()
    const responseUser = await (
      await registerMutation(registerData).unwrap()
    ).data
    dispatch(register(responseUser))
    navigate({ to: '/profile' })
  }

  const textData = {
    title: t('register.title'),
    nameInput: t('register.inputs.name'),
    emailInput: t('register.inputs.email'),
    passwordInput: t('register.inputs.password'),
    formButton: t('register.inputs.button'),
  }

  return {
    logged,
    handleRegisterChange,
    handleRegisterSubmit,
    isLoading,
    registerData,
    textData,
  }
}
