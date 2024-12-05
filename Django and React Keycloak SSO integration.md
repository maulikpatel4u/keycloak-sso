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

**3. Create the custom keycloak authentication class**
- Create the custom Keycloak authentication class for DRF auth.

  `app/authentication.py`
  ```python
  import logging
  from app_name.models.users import User
  from rest_framework.status import HTTP_401_UNAUTHORIZED
  from rest_framework.authentication import BaseAuthentication
  from rest_framework.exceptions import AuthenticationFailed
  from app_name.keycloak import KeycloakService

  logger = logging.getLogger('main')

  UNAUTHORIZED_MSG = "Unauthorized. Invalid authentication token."


  class KeycloakAuthentication(BaseAuthentication):
      """
      Custom authentication class to validate Keycloak tokens using DRF's BaseAuthentication.
      """
      def authenticate(self, request):
          """
          Authenticate the incoming request using a Keycloak token.
  
          Args:
              request (HttpRequest): The incoming HTTP request.

          Returns:
              tuple: (user, None) if authentication is successful.
              None: If no authentication is provided or invalid token.
        
          Raises:
              AuthenticationFailed: If the token is invalid or user cannot be authenticated.
          """
          try:
              # Extract the Authorization header
              auth_header = request.headers.get("Authorization")
              if not auth_header or not auth_header.startswith("Bearer "):
                  return None  # No token provided, let DRF handle unauthenticated requests
            
              # Extract the token from the Authorization header
              token = auth_header.split("Bearer ")[1]

              # Verify the token using Keycloak
              is_success, token_data = KeycloakService().verify_token(token)

              if not is_success:
                  raise AuthenticationFailed(UNAUTHORIZED_MSG, code=HTTP_401_UNAUTHORIZED)
            
              # Extract user email from the token payload
              email = token_data.get("email")
            
              # Retrieve the user from the database
              try:
                  user = User.objects.get(email=email, is_active=True)
              except ModelAccountUser.DoesNotExist:
                  logger.error(f"KeycloakAuthentication | No active user found for email: {email}")
                  raise AuthenticationFailed(UNAUTHORIZED_MSG, code=HTTP_401_UNAUTHORIZED)
            
              return user, None  # Return the authenticated user and None for the token
          except Exception as e:
              logger.error(f"KeycloakAuthentication | Error: {str(e)}")
              raise AuthenticationFailed(UNAUTHORIZED_MSG, code=HTTP_401_UNAUTHORIZED)
  ```

**4. Create the Backend Views**
- Create a `KeycloakService` that manages interactions with the Keycloak server, including generating authorization URLs, handling tokens, and retrieving user information.
- Define views in your `views.py` file:
  - Login View:
    - Redirects the user to Keycloak for authentication.
  - Callback View:
    - Expects a `code` from the frontend.
    - Exchange authorization code for tokens, sync user data, and return tokens to the frontend.
  - Refresh Token View:
    - Refresh an expired access token using the refresh token.
  - Logout View:
    -  Logs the user out by revoking the Keycloak session.

`app/keycloak.py`
```python
from keycloak import KeycloakOpenID
from app.settings import KEYCLOAK_CONFIG

import logging

logger = logging.getLogger("main")


class KeycloakService:
    """
    KeycloakService handles interactions with the Keycloak server, 
    including generating authorization URLs, managing tokens, and retrieving user information.
    """

    def __init__(self):
        """
        Initializes the Keycloak client using the configuration settings.
        """
        self.keycloak_openid = KeycloakOpenID(
            server_url=KEYCLOAK_CONFIG['SERVER_URL'],
            client_id=KEYCLOAK_CONFIG['CLIENT_ID'],
            realm_name=KEYCLOAK_CONFIG['REALM_NAME'],
            client_secret_key=KEYCLOAK_CONFIG['CLIENT_SECRET']
        )

    def get_auth_url(self, scope="openid email profile"):
        """
        Generates the Keycloak authorization URL.

        Args:
            scope (str): Space-separated scopes for authorization. Defaults to "openid email profile".

        Returns:
            tuple: (bool, str) where the first value indicates success and 
            the second is the auth URL or error message.
        """
        try:
            auth_url = self.keycloak_openid.auth_url(
                redirect_uri=KEYCLOAK_CONFIG['REDIRECT_URI'],
                scope=scope
            )
            return True, auth_url
        except Exception as e:
            logger.error(f"KeycloakService | get_auth_url - Error while generating auth URL: {str(e)}")
            return False, 'An error occurred. Please try again later.'
    
    def refresh_token(self, refresh_token):
        """
        Refreshes an expired access token using a refresh token.

        Args:
            refresh_token (str): The refresh token provided by Keycloak.

        Returns:
            tuple: (bool, dict or str) where the first value indicates success and 
            the second is the token data or error message.
        """
        try:
            if not refresh_token:
                return False, 'Refresh token not found.'
            
            token = self.keycloak_openid.refresh_token(refresh_token)
            return True, {
                "access_token": token.get('access_token'),
                "refresh_token": token.get('refresh_token'),
                "access_expires_in": token.get('expires_in'), # Time in seconds
                "refresh_expires_in": token.get('refresh_expires_in') # Time in seconds
            }
        except Exception as e:
            logger.error(f"KeycloakService | refresh_token - Error while refreshing token: {str(e)}")
            return False, 'Authentication failed: Invalid or expired refresh token.'
    
    def get_user_token(self, auth_code):
        """
        Exchanges an authorization code for tokens.

        Args:
            auth_code (str): The authorization code received from Keycloak.

        Returns:
            tuple: (bool, dict or str) where the first value indicates success and 
            the second is the token data or error message.
        """
        try:
            if not auth_code:
                return False, 'Authorization code not found.'
        
            # Exchange authorization code for tokens
            token = self.keycloak_openid.token(
                grant_type='authorization_code',
                code=auth_code,
                redirect_uri=KEYCLOAK_CONFIG['REDIRECT_URI']
            )

            return True, {
                "access_token": token.get('access_token'),
                "refresh_token": token.get('refresh_token'),
                "access_expires_in": token.get('expires_in'), # Time in seconds
                "refresh_expires_in": token.get('refresh_expires_in') # Time in seconds
            }
        except Exception as e:
            logger.error(f"KeycloakService | get_user_token - Error while getting user token data: {str(e)}")
            return False, 'Failed to exchange the authorization code for tokens. Please ensure the authorization code is valid and has not expired.'
    
    def get_user_info(self, access_token):
        """
        Retrieves user information using the access token.

        Args:
            access_token (str): The access token issued by Keycloak.

        Returns:
            tuple: (bool, dict or str) where the first value indicates success and 
            the second is user info or error message.
        """
        try:
            if not access_token:
                return False, 'Access token not found.'

            # Fetch user details using the access token
            user_info = self.keycloak_openid.userinfo(access_token)

            if not user_info:
                return False, 'Unable to retrieve user information.'
            
            return True, user_info
        except Exception as e:
            logger.error(f"KeycloakService | get_user_token - Error while getting user info: {str(e)}")
            return False, 'Something went wrong. Unable to retrieve user information.'
    
    def verify_token(self, token):
        """
        Verifies the authenticity of a token.

        Args:
            token (str): The token to be verified.

        Returns:
            tuple: (bool, dict or str) where the first value indicates success and 
            the second is token payload or error message.
        """
        try:
            token_data = self.keycloak_openid.decode_token(token)
            return True, token_data
        except Exception as e:
            logger.error(f"KeycloakService | verify_token - Error while verifying token: {str(e)}")
            return False, "Unauthorized. Invalid authentication token."
    
    def logout(self, refresh_token):
        """
        Logs the user out by revoking the Keycloak session.

        Args:
            refresh_token (str): The refresh token provided by Keycloak.

        Returns:
            tuple: (bool, str) where the first value indicates success and 
            the second is the success or error message.
        """
        try:
            if not refresh_token:
                return False, "Refresh token not found."
            
            self.keycloak_openid.logout(refresh_token)
            return True, "Successfully logged out."
        except Exception as e:
            logger.error(f"KeycloakService | verify_token - Error while verifying token: {str(e)}")
            return False, "Unauthorized. Invalid or expired refresh token."
```

`app/views.py`
```python
from django.shortcuts import redirect
from rest_framework.status import HTTP_200_OK, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED
from rest_framework.response import Response
from rest_framework.views import APIView
from app_name.models.users import User


class SSOLoginApiView(APIView):
    """
    Redirect the user to Keycloak's login page.
    """
    def get(self, request):
        is_success, auth_url = KeycloakService().get_auth_url()

        if not is_success:
            response = ApiResponse.error(message=auth_url)
            return Response(response, status=HTTP_400_BAD_REQUEST)
        
        return redirect(auth_url)


class AuthCallbackApiView(APIView):
    """
    Exchange authorization code for tokens, sync user data, and return tokens to the frontend.
    """
    def get(self, request):
        try:
            keycloak_manager = KeycloakService()
            
            is_success, token_data = keycloak_manager.get_user_token(request.query_params.get('code'))
            if not is_success:
                response = ApiResponse.error(message=token_data)
                return Response(response, status=HTTP_400_BAD_REQUEST)
            
            is_success, user_info = keycloak_manager.get_user_info(token_data.get('access_token'))
            if not is_success:
                response = ApiResponse.error(message=user_info)
                return Response(response, status=HTTP_400_BAD_REQUEST)
            
            try:
                # Sync user data in the database
                user, _ = User.objects.get_or_create(
                    email=user_info.get('email'),
                    defaults={
                        'first_name': user_info.get('given_name'),
                        'last_name': user_info.get('family_name'),
                    },
                )
            except Exception as e:
                logger.error(f"Error in get_or_create user: {str(e)}")
                response = ApiResponse.error(message='An error occurred. Please try again later.')
                return Response(response, status=HTTP_400_BAD_REQUEST)
            
            response = ApiResponse.success(message="The user has been logged in successfully.", data=token_data)
            return Response(data=response, status=HTTP_200_OK)
        except Exception as e:
            logger.error(f"AuthCallbackApiView | GET Method - Error: {str(e)}")
            response = ApiResponse.error(message='Error while communicating with Keycloak.', data={"error": str(e)})
            return Response(response, status=HTTP_400_BAD_REQUEST)


class SSORefreshTokenView(APIView):
    """
    Refresh an expired access token using the refresh token.
    """
    def post(self, request):
        is_success, token = KeycloakService().refresh_token(request.data.get('refresh_token'))

        if not is_success:
            response = ApiResponse.error(message=token)
            return Response(response, status=HTTP_401_UNAUTHORIZED)
        
        response = ApiResponse.success(message="Your session has been updated successfully.", data=token)
        return Response(response, status=HTTP_200_OK)


class SSOLogoutApiView(APIView):
    """
    Logs the user out by revoking the Keycloak session.
    """
    def post(self, request):
        is_success, message = KeycloakService().logout(request.data.get('refresh_token'))
        
        if not is_success:
            response = ApiResponse.error(message=message)
            return Response(response, status=HTTP_401_UNAUTHORIZED)
        
        response = ApiResponse.success(message=message)
        return Response(response, status=HTTP_200_OK)
```

**5. Define URLs**
- Update `urls.py` to include the routes for the login and callback views.

	```python
  from django.urls import path
  from .views import SSOLoginApiView, AuthCallbackApiView, SSORefreshTokenView, SSOLogoutApiView
  
  urlpatterns = [
      path('sso/login/', SSOLoginApiView, name='sso-login'),
      path('sso/auth/callback/', AuthCallbackApiView, name='sso-auth-callback'),
      path("sso/token/refresh/", SSORefreshTokenView.as_view(), name="token-refresh"),
      path("sso/logout/", SSOLogoutApiView.as_view(), name="sso-logout"),
  ]
  ```

### **Frontend Setup**

**1. Trigger Login**
- The frontend calls `/login/` on the backend to initiate the login process.

**2. Keycloak Redirect**
- The user logs in via Keycloak, which redirects back to the frontend at `/callback/` with the `code`.

**3. Frontend Sends Code to Backend**
- After receiving the `code`, the frontend sends a request to `/auth/callback/` to exchange the code for tokens.
  
  ```javascript
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
