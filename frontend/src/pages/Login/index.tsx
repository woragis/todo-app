import { LoginView } from './view'
import { useLoginModel } from './model'

const Login = () => {
  const model = useLoginModel()

  return <LoginView {...model} />
}

export default Login
