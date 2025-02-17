import { useSelector } from 'react-redux'
import { useAppDispatch } from '../../redux_old/hooks'
import { toggleTheme } from '../../redux_old/slices/themeSlice'
import { RootState } from '../../redux_old/store'
import { ThemeButtonProps } from '../../types/themeButton.types'

export const useThemeButtonModel = ({
  navbarColor,
  navbarBackgroundColor,
}: ThemeButtonProps) => {
  const dispatch = useAppDispatch()
  const toggleCurrentTheme = () => dispatch(toggleTheme())
  const isDarkMode = useSelector((state: RootState) => state.theme.isDarkMode)

  return { toggleCurrentTheme, isDarkMode, navbarColor, navbarBackgroundColor }
}
