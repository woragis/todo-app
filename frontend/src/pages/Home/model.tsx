import { useSelector } from 'react-redux'
import { RootState } from '../../redux/store'
import { useTodos } from '../../hooks/useTodos'
import { useTranslation } from 'react-i18next'

export const useHomeModel = () => {
  const { t } = useTranslation()
  const todosTitle = t('todos.title')
  const todosNotFound = t('todos.not-found')

  const todos = useTodos()

  const themeColors = useSelector((state: RootState) => state.theme.colors)
  const dividerColor = themeColors.background.contrast

  return { todosTitle, todosNotFound, todos, dividerColor }
}
