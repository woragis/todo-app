import { useProfileModel } from './model'

export const ProfileView = ({
  textData,
  user,
  logged,
}: ReturnType<typeof useProfileModel>) => {
  if (!logged) {
    return <h1>You are not logged in</h1>
  }
  return (
    <div>
      <h1>{textData.title}</h1>
      <h2>
        {textData.nameField}: {user.name}
      </h2>
      <hr />
      <p>
        {textData.emailField}: {user.email}
      </p>
      <p>
        {textData.passwordField}: {user.password}
      </p>
      <p>{/* {textData.createdField}: {user.created_at} */}</p>
      <p>{/* {textData.updatedField}: {user.updated_at} */}</p>
      <br />
      <small>Id: {user.id}</small>
    </div>
  )
}
