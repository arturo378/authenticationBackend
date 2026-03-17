# authenticationBackend

Node.js authentication REST API with JWT.

## Project Structure

```
authenticationBackend/
  src/
    config/db.js          - MongoDB connection
    models/User.js        - User model with password hashing
    controllers/authController.js - All auth logic
    middleware/auth.js     - JWT authentication & role authorization
    middleware/validate.js - Request validation rules
    routes/authRoutes.js   - Route definitions
    utils/tokens.js        - JWT token generation
    server.js              - Express app entry point
  .env                     - Environment variables
  .gitignore
  package.json
```

## API Endpoints

| Method | Route | Auth | Description |
|--------|-------|------|-------------|
| POST | `/api/auth/register` | No | Register a new user |
| POST | `/api/auth/login` | No | Login with email/password |
| POST | `/api/auth/logout` | Yes | Logout (invalidates refresh token) |
| POST | `/api/auth/refresh-token` | No | Get new access token via refresh token rotation |
| POST | `/api/auth/forgot-password` | No | Request password reset token |
| POST | `/api/auth/reset-password/:token` | No | Reset password with token |
| PATCH | `/api/auth/change-password` | Yes | Change password while logged in |
| GET | `/api/auth/me` | Yes | Get current user profile |
| PATCH | `/api/auth/update-profile` | Yes | Update name/email |
| DELETE | `/api/auth/delete-account` | Yes | Delete user account |

## Key Features

- **JWT access + refresh tokens** with httpOnly cookie storage and token rotation
- **Password hashing** with bcrypt (12 rounds)
- **Rate limiting** (20 requests per 15 min on auth routes)
- **Input validation** via express-validator
- **Role-based authorization** middleware (user/admin)
- **Secure password reset** flow with hashed tokens and expiry

## Getting Started

1. Update `.env` with your MongoDB URI and JWT secrets
2. `npm start` or `npm run dev` (with auto-reload)
