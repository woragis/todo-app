import { ChangeEvent, FormEvent, useState } from 'react'
import { useAppDispatch } from '../../redux/hooks'
import { useSelector } from 'react-redux'
import { RootState } from '../../redux/store'
import { register } from '../../redux/slices/authSlice'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { RegisterRequestInterface } from '../../types/axios.types'

export const useRegisterModel = () => {
  const { t } = useTranslation()
  const dispatch = useAppDispatch()
  const navigate = useNavigate()
  const auth = useSelector((state: RootState) => state.auth)

  const [registerData, setRegisterData] = useState<RegisterRequestInterface>(
    {} as RegisterRequestInterface
  )

  const handleRegisterChange = (event: ChangeEvent<HTMLInputElement>) => {
    setRegisterData((prevState) => ({
      ...prevState,
      [event.target.name]: event.target.value,
    }))
  }

  const handleRegisterSubmit = (event: FormEvent) => {
    event.preventDefault()
    console.log('Register data:', registerData)
    dispatch(register(registerData))
    navigate('/profile')
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
