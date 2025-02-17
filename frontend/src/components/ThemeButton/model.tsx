import { ThemeButtonProps } from '../../types/themeButton.types'
import { useAppDispatch, useAppSelector } from '@/redux/hooks'
import { toggleTheme } from '@/redux/theme/slice'

export const useThemeButtonModel = ({
  navbarColor,
  navbarBackgroundColor,
}: ThemeButtonProps) => {
  const dispatch = useAppDispatch()
  const toggleCurrentTheme = () => dispatch(toggleTheme())
  const isDarkMode = useAppSelector((state) => state.theme.mode)

  return { toggleCurrentTheme, isDarkMode, navbarColor, navbarBackgroundColor }
}
