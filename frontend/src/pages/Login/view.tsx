import { useForm } from '@tanstack/react-form'
import type { FieldApi } from '@tanstack/react-form'

import { useLoginModel } from './model'
import {
  Button,
  Form,
  FormContainer,
  ImgButton,
  Input,
} from '@/components/ui/Form.styles'

function FieldInfo({ field }: { field: FieldApi<any, any, any, any> }) {
  return (
    <>
      {field.state.meta.isTouched && field.state.meta.errors.length ? (
        <em>{field.state.meta.errors.join(', ')}</em>
      ) : null}
      {field.state.meta.isValidating ? 'haha elementValidating...' : null}
    </>
  )
}

export const LoginView = ({
  textData,
  logged,
  loginData,
  handleLoginChange,
  handleLoginSubmit,
  isLoading,
}: ReturnType<typeof useLoginModel>) => {
  const form = useForm({
    defaultValues: loginData,
    onSubmit: async ({ value }) => {
      // Do something with form data
      console.log(value)
    },
  })
  const formComponent = (
    <Form onSubmit={handleLoginSubmit}>
      {/* <h1>{textData.title}</h1> */}
      <Input
        type='email'
        name='email'
        id='email'
        placeholder={textData.emailInput}
        value={loginData.email}
        onChange={handleLoginChange}
      />
      <Input
        type='password'
        minLength={8}
        name='password'
        id='password'
        placeholder={textData.passwordInput}
        value={loginData.password}
        onChange={handleLoginChange}
      />
      <ImgButton />
      <Button>{textData.formButton}</Button>
    </Form>
  )

  if (isLoading) return <h1>Loading</h1>
  return (
    <FormContainer>
      <h1>Simple Form Example</h1>
      <form
        onSubmit={(e) => {
          e.preventDefault()
          e.stopPropagation()
          form.handleSubmit()
        }}
      >
        <div>
          {/* A type-safe field component*/}
          <form.Field
            name='email'
            validators={{
              onChange: ({ value }) =>
                !value
                  ? 'A first name is required'
                  : value.length < 3
                  ? 'First name must be at least 3 characters'
                  : undefined,
              onChangeAsyncDebounceMs: 500,
              onChangeAsync: async ({ value }) => {
                await new Promise((resolve) => setTimeout(resolve, 1000))
                return (
                  value.includes('error') && 'No "error" allowed in first name'
                )
              },
            }}
            children={(field) => {
              // Avoid hasty abstractions. Render props are great!
              return (
                <>
                  <label htmlFor={field.name}>Email</label>
                  <input
                    id={field.name}
                    name={field.name}
                    value={field.state.value}
                    onBlur={field.handleBlur}
                    onChange={(e) => field.handleChange(e.target.value)}
                  />
                  <FieldInfo field={field} />
                </>
              )
            }}
          />
        </div>
        <div>
          <form.Field
            name='password'
            children={(field) => (
              <>
                <label htmlFor={field.name}>Password</label>
                <input
                  id={field.name}
                  name={field.name}
                  value={field.state.value}
                  onBlur={field.handleBlur}
                  onChange={(e) => field.handleChange(e.target.value)}
                />
                <FieldInfo field={field} />
              </>
            )}
          />
        </div>
        <form.Subscribe
          selector={(state) => [state.canSubmit, state.isSubmitting]}
          children={([canSubmit, isSubmitting]) => (
            <button
              type='submit'
              disabled={!canSubmit}
            >
              {isSubmitting ? '...' : 'Submit'}
            </button>
          )}
        />
      </form>
      {logged && <h1>You are already logged in</h1>}
      {!logged && formComponent}
    </FormContainer>
  )
}
