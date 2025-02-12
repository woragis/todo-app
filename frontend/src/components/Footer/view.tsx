import { useFooterModel } from './model'
import {
  FooterBrand,
  FooterContainer,
  FooterLink,
  FooterListItem,
  FooterMediaIcons,
  FooterMenu,
  StyledFooter,
} from './styles'

export const FooterView = ({
  footerColors,
  brandName,
  menuLinks,
  mediaLinks,
}: ReturnType<typeof useFooterModel>) => {
  const menuComponent = menuLinks.map((link) => {
    return (
      <FooterListItem>
        <FooterLink to={link.path}>{link.title}</FooterLink>
      </FooterListItem>
    )
  })

  const socialMediaComponent = mediaLinks.map((socialMedia) => {
    return <FooterLink to={socialMedia.path}>{socialMedia.element}</FooterLink>
  })

  return (
    <StyledFooter
      color={footerColors.contrast}
      backgroundColor={footerColors.background}
      weakColor={footerColors.weak}
      id='footer'
    >
      <FooterContainer>
        <div className='col1'>
          <FooterBrand to=''>{brandName}</FooterBrand>
        </div>
        <div className='col2'>
          <FooterMenu className='menu'>{menuComponent}</FooterMenu>
        </div>
        <div className='col3'>
          <FooterMediaIcons className='media-icons'>
            {socialMediaComponent}
          </FooterMediaIcons>
        </div>
      </FooterContainer>
    </StyledFooter>
  )
}
