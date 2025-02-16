import {
  Button,
  Form,
  FormContainer,
  Input,
} from '../../components/ui/Form.styles'
import { useRegisterModel } from './model'

export const RegisterView = ({
  textData,
  auth,
  registerData,
  handleRegisterChange,
  handleRegisterSubmit,
}: ReturnType<typeof useRegisterModel>) => {
  if (auth.user) {
    return <h1>You are already logged in</h1>
  }
  return (
    <FormContainer>
      <Form onSubmit={handleRegisterSubmit}>
        <h1>{textData.title}</h1>
        <Input
          type='text'
          name='name'
          id='name'
          placeholder={textData.nameInput}
          value={registerData.name || ''}
          onChange={handleRegisterChange}
        />
        <Input
          type='text'
          name='email'
          id='email'
          placeholder={textData.emailInput}
          value={registerData.email || ''}
          onChange={handleRegisterChange}
        />
        <Input
          type='password'
          name='password'
          id='password'
          placeholder={textData.passwordInput}
          value={registerData.password || ''}
          onChange={handleRegisterChange}
        />
        <Button>{textData.formButton}</Button>
        {auth.status === 'loading' && <p>Loading...</p>}
        {auth.error && <p style={{ color: 'red' }}>{auth.error}</p>}
      </Form>
    </FormContainer>
  )
}
