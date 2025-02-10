import { useSelector } from 'react-redux'
import { useAppDispatch } from '../../redux/hooks'
import { toggleTheme } from '../../redux/slices/themeSlice'
import { RootState } from '../../redux/store'
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
