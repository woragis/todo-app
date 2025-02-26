# Backend

## Code organization

- [x] - Format Imports
- [x] - Padronize **Responses**
- [ ] - Implement Logging
  - [x] - Configure Logging
  - [ ] - Implement Logging for handlers
- [ ] - Rate limit middleware
  - [ ] - Create rate limit
  - [ ] - Implement rate limit middleware

### Documentation

- [x] - Add comments to Data
  - [x] - Cache
  - [x] - Database
  - [x] - Tables
- [ ] - Add comments to Handlers
  - [ ] - Auth
  - [ ] - Profile
  - [ ] - Todo
  - [ ] - User
- [ ] - Add comments to Middlewares
  - [ ] - rate limit
- [ ] - Add comments to Models
  - [ ] - Auth
  - [ ] - Jwt
  - [ ] - Todo
  - [ ] - User
  - [ ] - Response
- [ ] - Add comments to Routes
  - [ ] - Auth
  - [ ] - Profile
  - [ ] - Todo
  - [ ] - User
- [ ] - Add comments to Utils
  - [ ] - Bcrypt
  - [ ] - Encryption
  - [ ] - Jwt
  - [ ] - Regex
  - [ ] - Auth rate limit

### Logging

- [x] - Add logging to Data
  - [x] - Cache
  - [x] - Database
  - [x] - Tables
- [ ] - Add logging to Handlers
  - [ ] - Auth
  - [ ] - Profile
  - [ ] - Todo
  - [ ] - User
- [ ] - Add logging to Middlewares
  - [ ] - rate limit
- [ ] - Add logging to Models
  - [ ] - Auth
  - [ ] - Jwt
  - [ ] - Todo
  - [ ] - User
  - [ ] - Response
- [x] - Add logging to Utils
  - [x] - Bcrypt
  - [x] - Encryption
  - [x] - Jwt
  - [x] - Regex
  - [ ] - Auth rate limit

## Security

- [ ] - Update model (add hashed_email and encrypted_email and remove email)
  - [ ] - Encrypt email with SHA512 to hashed_email
  - [ ] - Encrypt email with AES512 to encrypted_email
- [x] - Encrypt PASSWORD with bcrypt
- [x] - JWT
  - [x] - Sub -> user_id as String
  - [x] - Role -> hashed with SHA512 as String
- [x] - UUID
- [x] - TODOS CRUD
  - [ ] - Admins can see everyone's TODOS
  - [ ] - Hash
    - [ ] - Use user_id as key? NO. use it as secondary key? Maybe
- [x] - USERS CRUD
  - [x] - 'users/\*' requires admin role through JWT
  - [x] - Regex to: 'create, update'
  - [x] - Bcrypt to: 'create, update'
- [ ] - Auth
  - [x] - 'profile/\*' requires 'Authorization: Bearer <token>' header
  - [x] - 'profile/update' only updates: name, email
  - [x] - 'profile/update-password' only updates: password
  - [ ] - 'profile/update' uses regex
  - [ ] - 'profile/update-password' uses bcrypt
  - [ ] - 'profile/update-password' uses regex
- [x] - Regex validation
  - [x] - Make regex validations global

## Business Logic

- [x] - Change framework from axum to actix
- [x] - Add roles to users model/table
- [x] - Add profile_picture to users model/table
- [x] - Add profile CRUD profile_picture handlers
- [ ] - Handlers
  - [x] - Add admin permission to CRUD TODOS and USERS
  - [x] - Add regex validation to REGISTER handler
  - [x] - Add regex validation to profile update handler
  - [x] - Add Bcrypt to LOGIN/REGISTER handlers
  - [x] - Format Imports
    - [x] - Reimport everything
- [x] - Implement **JWT** on Login & Register
- [x] - Implement **JWT** on todos CRUD
- [x] - Implement **Cache** _with_ **REDIS**
- [ ] - Implement **Cache** for USERS CRUD

### Cache

- [ ] - Implement Cache for recent requests and DB queries
  - [x] - Implement cache for Todos
    - [x] - Create
    - [x] - GetById
    - [x] - GetMany
    - [x] - Update
    - [x] - Delete
  - [x] - Implement cache for USERS
    - [x] - Create
    - [x] - GetById
    - [x] - GetMany
    - [x] - Update
    - [x] - Delete
  - [x] - Implement cache for PROFILE
    - [ ] - Read
    - [ ] - Read profile picture
- [x] - Create Rate Limit
- [ ] - Implement Rate limit as middleware or in every handler
  - [ ] - Add to all Todos handlers
  - [ ] - Add to all Users handlers
  - [ ] - Add to all Auth handlers
- [ ] - Implement Cache for Login/Register Limit

## Infra

- [x] - Fix DB connection on kubernetes

## CI/CD

- [ ] - Implement **Tests**
- [ ] - Create Github Action de Testes
- [ ] - Create Github Action de Deploy automatico para a **Playstore** e **Apple store**
