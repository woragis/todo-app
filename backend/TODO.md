# Backend

## Business Logic

- [x] - Change framework from axum to actix
- [ ] - Add roles to users model/table
- [ ] - Handlers
  - [ ] - Add admin permission to CRUD TODOS and USERS
  - [ ] - Add Bcrypt to LOGIN/REGISTER handlers
- [x] - Implement **JWT** on Login & Register
- [x] - Implement **JWT** on todos CRUD
- [ ] - Implement **Cache** _with **REDIS** or **MEM CACHED**_
- [ ] - Implement Cache for recent requests and DB queries
- [ ] - Implement Cache for Login/Register Limit
- [x] - Padronize **Responses**

## Infra

- [x] - Fix DB connection on kubernetes

## CI/CD

- [ ] - Implement **Tests**
- [ ] - Create Github Action de Testes
- [ ] - Create Github Action de Deploy automatico para a **Playstore** e **Apple store**
