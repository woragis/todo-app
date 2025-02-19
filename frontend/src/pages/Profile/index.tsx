import { ProfileView } from './view'
import { useProfileModel } from './model'

const Profile = () => {
  const model = useProfileModel()

  return <ProfileView {...model} />
}

export default Profile
