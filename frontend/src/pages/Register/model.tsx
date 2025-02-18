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
  const auth = useAppSelector((state) => state.auth)

  const [registerData, setRegisterData] = useState<RegisterRequestInterface>({
    name: '',
    email: '',
    password: '',
  })

  const [registerMutation, { data, isSuccess }] = useRegisterMutation()

  const handleRegisterChange = (event: ChangeEvent<HTMLInputElement>) => {
    setRegisterData((prevState) => ({
      ...prevState,
      [event.target.name]: event.target.value,
    }))
  }

  const handleRegisterSubmit = (event: FormEvent) => {
    event.preventDefault()
    console.log('Register data:', registerData)
    registerMutation(registerData).then(() => {
      if (data && isSuccess) dispatch(register(data.data))
    })
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
    textData,
    auth,
    registerData,
    handleRegisterChange,
    handleRegisterSubmit,
  }
}
