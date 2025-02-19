import { useTranslation } from 'react-i18next'

import { useAppSelector } from '@/features/hooks'
import { useGetTodosQuery } from '@/features/todos/apiSlice'

export const useHomeModel = () => {
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
