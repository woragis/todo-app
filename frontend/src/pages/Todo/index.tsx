import { useTodoModel } from './model'
import { TodoView } from './view'

const Todo = () => {
  const model = useTodoModel()

  return <TodoView {...model} />
}

export default Todo
