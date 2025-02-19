import { ThemeButtonView } from './view'
import { useThemeButtonModel } from './model'

import { ThemeButtonProps } from '@/types/themeButton.types'

const ThemeButton = (props: ThemeButtonProps) => {
  const model = useThemeButtonModel(props)

  return <ThemeButtonView {...model} />
}

export default ThemeButton
