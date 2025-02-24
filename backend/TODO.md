# Backend

## Documentation

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

## Business Logic

- [x] - Change framework from axum to actix
- [x] - Add roles to users model/table
- [x] - Add profile_picture to users model/table
- [x] - Add profile CRUD profile_picture handlers
- [ ] - Handlers
  - [ ] - Add admin permission to CRUD TODOS and USERS
  - [x] - Add regex validation to REGISTER handler
  - [ ] - Add regex validation to profile update handler
  - [x] - Add Bcrypt to LOGIN/REGISTER handlers
  - [ ] - Separate params
  - [x] - Format Imports
    - [x] - Reimport everything
- [x] - Format Imports
- [x] - Implement **JWT** on Login & Register
- [x] - Implement **JWT** on todos CRUD
- [x] - Padronize **Responses**
- [ ] - Implement Logging
  - [x] - Configure Logging
  - [ ] - Implement Logging for handlers
- [ ] - Implement **Cache** _with_ **REDIS**

### Cache

- [ ] - Implement Cache for recent requests and DB queries
  - [x] - Implement cache for Todos
    - [x] - Create
    - [x] - GetById
    - [x] - GetMany
    - [x] - Update
    - [x] - Delete
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
