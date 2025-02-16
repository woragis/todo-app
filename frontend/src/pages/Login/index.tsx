import { useLoginModel } from "./model";
import { LoginView } from "./view";

const Login = () => {
  const model = useLoginModel();

  return <LoginView {...model} />;
};

export default Login;
