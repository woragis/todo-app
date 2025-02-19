import { NotFoundView } from './view'
import { useNotFoundModel } from './model'

const NotFound = () => {
  const model = useNotFoundModel()

  return <NotFoundView {...model} />
}

export default NotFound
