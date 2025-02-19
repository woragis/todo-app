import { FooterView } from './view'
import { useFooterModel } from './model'

const Footer = () => {
  const model = useFooterModel()

  return <FooterView {...model} />
}

export default Footer
