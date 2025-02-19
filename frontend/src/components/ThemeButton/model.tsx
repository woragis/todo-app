import { ThemeButtonProps } from '@/types/themeButton.types'
import { toggleTheme } from '@/features/theme/slice'
import { useAppDispatch, useAppSelector } from '@/features/hooks'

export const useThemeButtonModel = ({
  navbarColor,
  navbarBackgroundColor,
}: ThemeButtonProps) => {
  const dispatch = useAppDispatch()
  const toggleCurrentTheme = () => dispatch(toggleTheme())
  const theme = useAppSelector((state) => state.theme.mode)

  return { toggleCurrentTheme, theme, navbarColor, navbarBackgroundColor }
}
