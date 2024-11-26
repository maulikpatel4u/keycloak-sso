### **Django and React Keycloak SSO integration**
---

**Workflow**

**1. Frontend Initiates Login**
- The frontend sends a request to the backend's `/auth/callback/` endpoint to initiate the login process.

**2. Backend Redirects to Keycloak**
- The backend constructs a Keycloak login URL with necessary parameters (e.g., client ID, redirect URI) and redirects the user to Keycloak's login page.

**3. Keycloak Authenticates User**
- The user logs in on Keycloak's login page.
- After successful login, Keycloak redirects the user to the frontend with an authorization code in the query parameters.

**4. Frontend Receives Authorization Code**
- The frontend captures the code parameter from the URL returned by Keycloak after login.
- The frontend sends this code to the backend's `/auth/callback/` endpoint to exchange it for access and refresh tokens.

**5. Backend Exchanges Code for Tokens**
- The backend's `/auth/callback/` endpoint sends the authorization code to Keycloak's token endpoint.
- Keycloak responds with:
  - `access_token`: Used for authentication in subsequent API requests.
  - `refresh_token`: Used to obtain a new access token when it expires.
  - `expires_in`: The duration (in seconds) for which the access token is valid.
  - `refresh_expires_in`: The duration (in seconds) for which the refresh token is valid.

**6. Tokens Sent to Frontend**
- The backend returns the access and refresh tokens to the frontend.
- The frontend securely stores these tokens (e.g., in HttpOnly cookies or local storage)
