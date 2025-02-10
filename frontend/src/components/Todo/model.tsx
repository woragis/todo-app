import { useParams } from 'react-router-dom'
import { useAppDispatch } from '../../redux/hooks'
import { getTodo } from '../../redux/slices/todosSlice'
import { RootState } from '../../redux/store'
import { useSelector } from 'react-redux'

export const useTodoModel = () => {
  const { id } = useParams()

  const dispatch = useAppDispatch()
  dispatch(getTodo(id))

  const todo = useSelector((state: RootState) => state.todos.currentTodo)

  return { todo }
}
