import { Link } from '@tanstack/react-router'
import styled from '@emotion/styled'

interface FooterStyleProps {
  color: string
  weakColor: string
  backgroundColor: string
}
export const StyledFooter = styled.footer<FooterStyleProps>`
  --color: ${(_) => _.color};
  --weak-color: ${(_) => _.weakColor};
  --background: ${(_) => _.backgroundColor};
  color: var(--color);
  background-color: var(--background);
  padding: 30px;
  text-align: center;

  a {
    color: var(--color);
    text-decoration: none;
  }

  h4 {
    margin-bottom: 1em;
    text-transform: uppercase;
  }
`

export const FooterMediaIcons = styled.ul`
  margin: 1.5em 0;
  display: flex;
  justify-content: center;
  align-items: center;
  padding: 0.5em 0;
  gap: 0.5em;
  li {
    display: inline-block;
  }
  a {
    border-radius: 50%;
    border: 1px var(--weak-color) solid;
    font-size: 1.1em;
    width: 2em;
    height: 2em;
    svg {
      fill: var(--weak-color);
    }
    &:hover {
      svg {
        fill: var(--color);
      }
      border-color: var(--color);
    }
  }
`

export const FooterBrand = styled(Link)`
  display: block;
  font-size: 1.8em;
  font-weight: 600;
  margin-bottom: 1em;
  margin: 0;
`

export const FooterListItem = styled.li`
  display: inline-block;
  margin: 1em;
  text-align: center;
`

export const FooterMenu = styled.ul`
  list-style-type: none;
  a {
    transition: 300ms;
    font-weight: 300;
    color: var(--weak-color);
    &:hover {
      color: var(--color);
      text-decoration: none;
    }
  }
`

export const FooterLink = styled(Link)`
  color: var(--weak-color);
  text-decoration: none;
  display: flex;
  justify-content: center;
  align-items: center;
  transition: 300ms;

  &:hover {
    color: var(--color);
    text-decoration: underline;
  }
`

export const FooterTitle = styled.h4`
  margin-bottom: 1em;
  text-transform: uppercase;
`

export const FooterContainer = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  text-align: center;
  gap: 2em;
  max-width: 1200px;
  margin: 0 auto;
  padding: 2em;
`
