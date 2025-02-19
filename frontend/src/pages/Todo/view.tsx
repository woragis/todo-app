import { useTodoModel } from './model'
import {
  StyledTodo,
  StyledTodoBody,
  StyledTodoId,
  StyledTodoTitle,
} from './styles'

export const TodoView = ({
  todo,
  isLoading,
  isSuccess,
}: ReturnType<typeof useTodoModel>) => {
  if (isLoading) {
    return <h1>Loading..</h1>
  }
  if (!isSuccess || !todo) return <h1>did not find todo</h1>

  return (
    <StyledTodo>
      <StyledTodoId>id: {todo.id}</StyledTodoId>
      <StyledTodoTitle
        type='text'
        value={todo.title}
      />
      <StyledTodoBody value={todo.description} />
    </StyledTodo>
  )
}
