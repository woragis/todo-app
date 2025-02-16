import { useHomeModel } from './model'
import { HomeView } from './view'

const Home = () => {
  const model = useHomeModel()

  return <HomeView {...model} />
}

export default Home
