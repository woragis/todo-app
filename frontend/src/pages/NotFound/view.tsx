import { useNotFoundModel } from './model'
import { StyledNotFound } from './styles'

export const NotFoundView = ({
  pageUrl,
}: ReturnType<typeof useNotFoundModel>) => {
  console.log(pageUrl.pathname)

  return (
    <StyledNotFound>
      <h1>404</h1>
      <br />
      <span>{pageUrl.pathname}</span>
      <h3>Page Not Found</h3>
    </StyledNotFound>
  )
}
