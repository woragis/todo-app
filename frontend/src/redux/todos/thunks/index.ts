import addAsyncBulider, { todosAddAsync } from './add'
import deleteAsyncBulider, { todosDeleteAsync } from './delete'
import editAsyncBulider, { todosEditAsync } from './edit'
import fetchAsyncBulider, { todosFetchAsync } from './fetch'

export const TODOS_BASE_URL = 'http://localhost:8080/todos'

export {
  addAsyncBulider,
  deleteAsyncBulider,
  editAsyncBulider,
  fetchAsyncBulider,
  todosAddAsync,
  todosDeleteAsync,
  todosEditAsync,
  todosFetchAsync,
}
