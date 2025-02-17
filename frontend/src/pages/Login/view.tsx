import {
  Button,
  Form,
  FormContainer,
  Input,
} from '../../components/ui/Form.styles'
import { useLoginModel } from './model'

export const LoginView = ({
  textData,
  auth,
  loginData,
  handleLoginChange,
  handleLoginSubmit,
}: ReturnType<typeof useLoginModel>) => {
  const formComponent = (
    <Form onSubmit={handleLoginSubmit}>
      {/* <h1>{textData.title}</h1> */}
      <Input
        type='text'
        name='email'
        id='email'
        placeholder={textData.emailInput}
        value={loginData.email}
        onChange={handleLoginChange}
      />
      <Input
        type='text'
        name='password'
        id='password'
        placeholder={textData.passwordInput}
        value={loginData.password}
        onChange={handleLoginChange}
      />
      <Button>{textData.formButton}</Button>
    </Form>
  )

  return (
    <FormContainer>
      {auth.user && <h1>You are already logged in</h1>}
      {!auth.user && formComponent}
    </FormContainer>
  )
}
