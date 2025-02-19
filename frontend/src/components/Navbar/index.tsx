import { NavbarView } from './view'
import { useNavbarModel } from './model'

const Navbar = () => {
  const model = useNavbarModel()

  return <NavbarView {...model} />
}

export default Navbar
