import { HomeView } from './view'
import { useHomeModel } from './model'

const Home = () => {
  const model = useHomeModel()

  return <HomeView {...model} />
}

export default Home
