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
- The frontend securely stores these tokens (e.g., in `HttpOnly cookies` or `local storage`)

### **Backend Setup**

The Django backend will redirect the user to Keycloak for authentication. After successful login, Keycloak redirects the user back to the frontend with the authorization code. The frontend captures this code and sends it to the backend via an API to exchange it for access and refresh tokens. The tokens are then returned to the frontend for secure storage and API requests.

**1. Install Keycloak Dependencies**
- You will need `python-keycloak` to interact with Keycloak APIs.

  ```python
  pip install python-keycloak==4.7.3
  ```

**2. Configure Django Settings**
- Update your `settings.py` file to include the necessary Keycloak configurations.
  
  ```python
  REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
      'app_name.authentication.KeycloakAuthentication', # Custom keycloak auth class for DRF
    ),
  }

  # Keycloak SSO Configuration
  KEYCLOAK_CONFIG = {
    "SERVER_URL": "http://localhost:8080",  # Keycloak server URL
    "REALM_NAME": "realm-name",  # Keycloak realm
    "CLIENT_ID": "client-ID",  # Client ID for your app
    "CLIENT_SECRET": "client-secret",  # Client secret generated in Keycloak
    "REDIRECT_URI": "http://localhost:8000/api/auth/callback/"  # Callback URL after login
  }
  ```

**3. Create the Backend Views**
- Define two views in your `views.py` file:
  - Login View:
    - Redirects the user to Keycloak for authentication.
  - Callback View:
    - Expects a `code` from the frontend.
    - Exchange authorization code for tokens, sync user data, and return tokens to the frontend.

```python
import requests
from django.shortcuts import redirect
from urllib.parse import urlencode
from rest_framework.response import Response
from rest_framework.views import APIView
from accounts.models.users import ModelAccountUser
from demo_site.settings.settings import KEYCLOAK_SERVER_URL, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID, \
		KEYCLOAK_CALLBACK_URL, KEYCLOAK_CLIENT_SECRET

class SSOLoginApiView(APIView):
    """
    Redirect the user to Keycloak's login page.
    """

    def get(self, request):        
        keycloak_url = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth"
        params = {
            'client_id': KEYCLOAK_CLIENT_ID,
            'redirect_uri': KEYCLOAK_CALLBACK_URL,
            'response_type': 'code',
            'scope': 'openid email profile',
        }
        return redirect(f"{keycloak_url}?{urlencode(params)}")

class AuthCallbackApiView(APIView):
    """
    Exchange authorization code for tokens, sync user data, and return tokens to the frontend.
    """

    def get(self, request):        
        code = request.GET.get('code')
        if not code:
            response = ApiResponse.error(message='Authorization code not found.')
            return Response(response, status=HTTP_400_BAD_REQUEST)

        # Exchange authorization code for tokens
        token_url = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': KEYCLOAK_CALLBACK_URL,
            'client_id': KEYCLOAK_CLIENT_ID,
            'client_secret': KEYCLOAK_CLIENT_SECRET,
        }
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        try:
            token_response = requests.post(token_url, data=data, headers=headers)
            if token_response.status_code == 200:
                tokens = token_response.json()
                access_token = tokens.get('access_token')

                # Fetch user info from Keycloak using the access token
                userinfo_url = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/userinfo"
                userinfo_response = requests.get(userinfo_url, headers={'Authorization': f'Bearer {access_token}'})

                if userinfo_response.status_code == 200:
                    userinfo = userinfo_response.json()
                
                # Sync user data in the database
                user, _ = ModelAccountUser.objects.get_or_create(
                    email=userinfo.get('email', ''),
                    defaults={
                        'first_name': userinfo.get('given_name', ''),
                        'last_name': userinfo.get('family_name', ''),
                    },
                )
                
                # Respond with tokens and user data
                response_data = {
                    "auth": tokens,
                    "user": {
                        "id": user.id,
                        "email": user.email,
                        "first_name": user.first_name,
                        "last_name": user.last_name,
                        "full_name": f"{user.first_name} {user.last_name}"
                    },
                }
                response = ApiResponse.success(message="The user has been logged in successfully.", data=response_data)
                return Response(data=response, status=HTTP_200_OK)
            else:
                response = ApiResponse.error(
                    message='Failed to exchange the authorization code for tokens.',
                    data=token_response.json()
                )
                return Response(response, status=HTTP_400_BAD_REQUEST)
        except requests.exceptions.RequestException as e:
            response = ApiResponse.error(message='Error communicating with Keycloak.', data={"error": str(e)})
            return Response(response, status=HTTP_400_BAD_REQUEST)
```

**4. Define URLs**
- Update `urls.py` to include the routes for the login and callback views.

	```python
  from django.urls import path
  from .views import SSOLoginApiView, AuthCallbackApiView
  
  urlpatterns = [
      path('sso/login/', SSOLoginApiView, name='sso-login'),
      path('sso/auth/callback/', AuthCallbackApiView, name='sso-auth-callback'),
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
	    const response = await fetch(`<Backend-URL>/api/sso/auth/callback/?code=${authCode}`);
	    const tokens = await response.json();
	    console.log(tokens);
	    // Store tokens securely, e.g., HttpOnly cookies, localStorage, etc.
	};
  ```

**4. Store the Token in Frontend**
- Once the frontend receives the token from the backend (in the `/auth/callback/` response), it can store the JWT in `HttpOnly cookies` or `local storage` and send it in the Authorization header for subsequent API calls.

> [!IMPORTANT]
> **Security Considerations**
> - Never expose sensitive details like the `client_secret` to the frontend.
> - Use HTTPS for all communications between frontend, backend, and Keycloak.
> - Ensure proper token storage in the frontend (e.g., using `HttpOnly cookies`).
> - Consider token expiration and implement token refresh functionality in your backend if needed.
