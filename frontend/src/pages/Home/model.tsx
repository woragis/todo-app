import { useTranslation } from 'react-i18next'
import { useGetTodosQuery } from '@/redux/todos/apiSlice'
import { useAppSelector } from '@/redux/hooks'

export const useHomeModel = () => {
  const { t } = useTranslation()
  const todosTitle = t('todos.title')
  const todosNotFound = t('todos.not-found')

  const { data, isLoading, isError } = useGetTodosQuery()

  const themeColors = useAppSelector((state) => state.theme.colors)
  const dividerColor = themeColors.background.contrast

  return {
    todosTitle,
    todosNotFound,
    todos: data,
    isLoading,
    isError,
    dividerColor,
  }
}
