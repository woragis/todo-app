import { RegisterView } from './view'
import { useRegisterModel } from './model'

const Register = () => {
  const model = useRegisterModel()

  return <RegisterView {...model} />
}

export default Register
