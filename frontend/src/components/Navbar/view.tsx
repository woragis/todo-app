import LanguageSwitcher from '../LanguageSwitcher'
import Login from '../../pages/Login'
import Register from '../../pages/Register'
import ThemeButton from '../ThemeButton'
import { useNavbarModel } from './model'
import {
  NavbarInvisibleContainer,
  NavbarLogo,
  NavLink,
  NavLinkItem,
  NavLinksContainer,
  StyledNavbar,
} from './styles'

export const NavbarView = ({
  navLinks,
  authLinks,
  themeColors,
  navLogo,
  loginVisible,
  registerVisible,
}: ReturnType<typeof useNavbarModel>) => {
  const navLinksComponent = navLinks.map(({ title, path, onClick }) => {
    return (
      <NavLinkItem key={title + '_nav_link'}>
        <NavLink
          to={path ? path : ''}
          onClick={onClick}
        >
          {title}
        </NavLink>
      </NavLinkItem>
    )
  })

  const authLinksComponent = authLinks.map(({ title, path, onClick }) => {
    return (
      <NavLinkItem key={title + '_nav_link'}>
        <NavLink
          to={path ? path : ''}
          onClick={onClick}
        >
          {title}
        </NavLink>
      </NavLinkItem>
    )
  })

  window.addEventListener('scroll', () => {
    const header = document.querySelector('.navbar')
    header?.classList.toggle('sticky', window.scrollY > 0)
  })

  return (
    <NavbarInvisibleContainer>
      <StyledNavbar
        role='navigation'
        className='navbar'
        color={themeColors.navbar.background}
        backgroundColor={themeColors.navbar.contrast}
        invertedColor={themeColors.navbar.contrast}
        invertedBackgroundColor={themeColors.navbar.background}
      >
        <NavbarLogo src={navLogo} />
        <NavLinksContainer>
          {navLinksComponent}
          {authLinksComponent}
          <LanguageSwitcher />
          <ThemeButton
            navbarColor={themeColors.navbar.background}
            navbarBackgroundColor={themeColors.navbar.contrast}
          />
        </NavLinksContainer>
      </StyledNavbar>
      {loginVisible && <Login />}
      {registerVisible && <Register />}
    </NavbarInvisibleContainer>
  )
}
