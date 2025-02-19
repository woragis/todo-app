import { LanguageSwitcherView } from './view'
import { useLanguageSwitcherModel } from './model'

const LanguageSwitcher = () => {
  const model = useLanguageSwitcherModel()

  return <LanguageSwitcherView {...model} />
}

export default LanguageSwitcher
