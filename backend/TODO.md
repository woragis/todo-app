# Backend

## Code organization

- [x] - Format Imports
- [x] - Padronize **Responses**
- [ ] - Separate params
- [ ] - Implement Logging
  - [x] - Configure Logging
  - [ ] - Implement Logging for handlers
- [ ] - Rate limit
  - [ ] - Create rate limit
  - [ ] - Implement rate limit

### Documentation

- [ ] - Comments
  - [ ] - Add Comments to Handlers
    - [ ] - Auth
    - [ ] - Profile
    - [ ] - Todo
    - [ ] - User
  - [ ] - Add Comments to Models
    - [ ] - Auth
    - [ ] - Jwt
    - [ ] - Todo
    - [ ] - User
  - [ ] - Add Comments to Database
    - [ ] - Database Connection
    - [ ] - Database Tables
  - [ ] - Add Comments to Routes
    - [ ] - Auth
    - [ ] - Profile
    - [ ] - Todo
    - [ ] - User
  - [ ] - Add Comments to Utils
    - [ ] - Jwt
    - [ ] - Response
      - [ ] - Separate response models from utils

## Security

- [ ] - Encrypt data like EMAIL with SHA512
- [x] - Encrypt PASSWORD with bcrypt
- [x] - Use JWT
- [x] - Use UUID
- [x] - Use auth header for TODOS CRUD
- [ ] - USERS CRUD
  - [x] - Require admin role
  - [x] - Add regex validation
  - [x] - Add bcrypt to update and create handlers
- [x] - Remove password from profile/update
- [x] - Add update password route
- [x] - Put role in JWT
- [x] - Encrypt JWT role with AES
- [ ] - Regex validation
  - [ ] - Make regex validations global

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
