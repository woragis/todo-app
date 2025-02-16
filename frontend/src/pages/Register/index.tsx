import { useRegisterModel } from "./model";
import { RegisterView } from "./view";

const Register = () => {
  const model = useRegisterModel();

  return <RegisterView {...model} />;
};

export default Register;
