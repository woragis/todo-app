import { useTranslation } from 'react-i18next'

import { useAppSelector } from '@/features/hooks'
import { useGetTodosQuery } from '@/features/todos/apiSlice'
import { useNavigate } from '@tanstack/react-router'

export const useHomeModel = () => {
  const navigate = useNavigate()

  const { logged } = useAppSelector((state) => state.auth)
  if (!logged) navigate({ to: '/auth/login' })

  const { t } = useTranslation()
  const todosTitle = t('todos.title')
  const todosNotFound = t('todos.not-found')

  const { data: todos, isLoading, isError } = useGetTodosQuery()

  const dividerColor = useAppSelector(
    (state) => state.theme.colors.background.contrast
  )

  return {
    todosTitle,
    todosNotFound,
    todos,
    isLoading,
    isError,
    dividerColor,
  }
}
