import { Link } from '@tanstack/react-router'
import styled from '@emotion/styled'

import { NavbarProps } from '@/types/navbar.types'

export const NavbarInvisibleContainer = styled.header`
  background-color: transparent;
`

export const StyledNavbar = styled.nav<NavbarProps>`
  --padding-vertical: 40px;
  --padding-horizontal: 50px;
  &.sticky {
    --padding-vertical: 5px;
    padding: var(--padding-vertical) var(--padding-horizontal);
    background-color: ${(_) => _.invertedBackgroundColor};
    * {
      color: ${(_) => _.invertedColor};
    }
  }
  * {
    color: ${(_) => _.color};
  }
  font-family: 'Poppins', sans-serif;
  z-index: 2;
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  display: flex;
  justify-content: space-between;
  align-items: center;
  transition: 600ms;
  padding: var(--padding-vertical) var(--padding-horizontal);
`

export const NavbarLogo = styled.img`
  height: 2em;
  position: relative;
  font-weight: 700;
  margin: 0 50px;
  height: 50px;
  text-decoration: none;
  text-transform: uppercase;
  letter-spacing: 2px;
  transition: 600ms;
`

export const NavLinksContainer = styled.ul`
  position: relative;
  display: flex;
  justify-content: center;
  align-items: center;
`

export const NavLinkItem = styled.li`
  position: relative;
  list-style: none;
`

export const NavLink = styled(Link)`
  position: relative;
  margin: 0 15px;
  text-decoration: none;
  letter-spacing: 2px;
  font-weight: 500;
  transition: 600ms;
`
