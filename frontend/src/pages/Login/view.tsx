import {
  Button,
  Form,
  FormContainer,
  ImgButton,
  Input,
} from '@/components/ui/Form.styles'
import { useLoginModel } from './model'

export const LoginView = ({
  textData,
  auth,
  loginData,
  handleLoginChange,
  handleLoginSubmit,
  isLoading,
}: ReturnType<typeof useLoginModel>) => {
  const formComponent = (
    <Form onSubmit={handleLoginSubmit}>
      {/* <h1>{textData.title}</h1> */}
      <Input
        type='email'
        name='email'
        id='email'
        placeholder={textData.emailInput}
        value={loginData.email}
        onChange={handleLoginChange}
      />
      <Input
        type='password'
        minLength={8}
        name='password'
        id='password'
        placeholder={textData.passwordInput}
        value={loginData.password}
        onChange={handleLoginChange}
      />
      <ImgButton />
      <Button>{textData.formButton}</Button>
    </Form>
  )

  if (isLoading) return <h1>Loading</h1>
  return (
    <FormContainer>
      {auth.user && <h1>You are already logged in</h1>}
      {!auth.user && formComponent}
    </FormContainer>
  )
}
