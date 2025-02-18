import { useTodoModel } from './model'

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
    <div>
      <p>id: {todo.id}</p>
      <br />
      <h1>Title: {todo.title}</h1>
      <hr />
      <br />
      <p>{todo.description}</p>
    </div>
  )
}
