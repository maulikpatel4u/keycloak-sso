### **Django and React Keycloak Single Sign-On (SSO) integration**
---

### **Workflow**

**1. Frontend Initiates Login**
- The frontend sends a request to the backend's `/login/` endpoint to initiate the login process.

**2. Backend Redirects to Keycloak**
- The backend constructs a Keycloak login URL with necessary parameters (e.g., `client ID`, `redirect URI`) and redirects the user to Keycloak's login page.

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

### **Backend Setup**

The Django backend will redirect the user to Keycloak for authentication. After successful login, Keycloak redirects the user back to the frontend with the authorization code. The frontend captures this code and sends it to the backend via an API to exchange it for access and refresh tokens. The tokens are then returned to the frontend for secure storage and API requests.

**1. Install Keycloak Dependencies**
- You will need `django-keycloak` and `requests` to interact with Keycloak APIs.

  ```python
  pip install django-keycloak requests
  ```


**2. Configure Django Settings**
- Update your `settings.py` file to include the necessary Keycloak configurations.
  
  ```python
  INSTALLED_APPS = [
      # your other apps
      'django_keycloak',
  ]

  # Keycloak Configuration
  KEYCLOAK_SERVER_URL = "http://localhost:8080"  # Your Keycloak server URL
  KEYCLOAK_REALM = "MyRealm"  # Your Keycloak realm
  KEYCLOAK_CLIENT_ID = "APP1"  # Client ID for your app
  KEYCLOAK_CLIENT_SECRET = "your-client-secret"  # Client secret generated in Keycloak
  FRONTEND_REDIRECT_URI = "http://localhost:3000/callback/"  # Frontend URL for Keycloak redirect
  BACKEND_CALLBACK_URL = "http://localhost:8000/auth/callback/"  # Backend URL for exchanging the code
  ```


**3. Create the Backend Views**
- Define two views in your `views.py` file:
  - Login View:
    - Redirects the user to Keycloak for authentication.
  - Callback View:
    - Expects a `code` from the frontend.
    - Exchanges the authorization code for access and refresh tokens.

**4. Define URLs**
- Update `urls.py` to include the routes for the login and callback views.

  ```python
  from django.urls import path
  from .views import login, callback
  
  urlpatterns = [
      path('login/', login, name='login'),
      path('auth/callback/', callback, name='callback'),
  ]
  ```


### **Frontend Setup**

**1. Trigger Login**
- The frontend calls `/login/` on the backend to initiate the login process.

**2. Keycloak Redirect**
- The user logs in via Keycloak, which redirects back to the frontend at `/callback/` with the `code`.

**3. Frontend Sends Code to Backend**
- After receiving the `code`, the frontend sends a request to `/auth/callback/` to exchange the code for tokens.
  
  ```python
	const exchangeCodeForToken = async (authCode) => {
	    const response = await fetch(`<Backend-URL>/auth/callback/?code=${authCode}`);
	    const tokens = await response.json();
	    console.log(tokens);
	    // Store tokens securely, e.g., HttpOnly cookies, localStorage, etc.
	};
  ```

**4. Store the Token in Frontend**
- Once the frontend receives the token from the backend (in the `/auth/callback/` response), it can store the JWT in `HttpOnly` cookies or `local storage` and send it in the Authorization header for subsequent API calls.
