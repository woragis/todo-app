import { useTodoModel } from './model'

export const TodoView = ({ todo }: ReturnType<typeof useTodoModel>) => {
  if (!todo) {
    return <h1>Did not find todo</h1>
  }

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
