#!/usr/bin/env python3
"""Basic authentication module for the API.
"""
import re
import base64
import binascii
from typing import Tuple, TypeVar

from .auth import Auth
from models.user import User

class BasicAuth(Auth):
    """Basic authentication class.
    """
    def extract_base64_authorization_header(
            self,
            authorization_header: str) -> str:
        """Extracts the Base64 part of the Authorization header
        for Basic Authentication.
        """
        if authorization_header is None or not isinstance(authorization_header, str):
            raise ValueError("Invalid authorization header")
        
        pattern = r'Basic (?P<token>.+)'
        field_match = re.fullmatch(pattern, authorization_header.strip())
        
        if field_match is not None:
            return field_match.group('token')
        else:
            raise ValueError("Invalid authorization header format")

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str,
            ) -> str:
        """Decodes a base64-encoded authorization header.
        """
        if base64_authorization_header is None or not isinstance(base64_authorization_header, str):
            raise ValueError("Invalid base64 authorization header")

        try:
            res = base64.b64decode(
                base64_authorization_header,
                validate=True,
            )
            return res.decode('utf-8')
        except (binascii.Error, UnicodeDecodeError):
            raise ValueError("Error decoding base64 authorization header")

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str,
            ) -> Tuple[str, str]:
        """Extracts user credentials from a base64-decoded authorization
        header that uses the Basic authentication flow.
        """
        if decoded_base64_authorization_header is None or not isinstance(decoded_base64_authorization_header, str):
            raise ValueError("Invalid decoded base64 authorization header")

        pattern = r'(?P<user>[^:]+):(?P<password>.+)'
        field_match = re.fullmatch(
            pattern,
            decoded_base64_authorization_header.strip(),
        )
        if field_match is not None:
            user = field_match.group('user')
            password = field_match.group('password')
            return user, password
        else:
            raise ValueError("Invalid decoded authorization header format")

    def user_object_from_credentials(
            self,
            user_email: str,
            user_pwd: str) -> TypeVar('User'):
        """Retrieves a user based on the user's authentication credentials.
        """
        if user_email is None or user_pwd is None or not isinstance(user_email, str) or not isinstance(user_pwd, str):
            raise ValueError("Invalid user credentials")

        try:
            users = User.search({'email': user_email})
        except Exception:
            raise ValueError("Error searching for user")

        if len(users) <= 0:
            return None
        if users[0].is_valid_password(user_pwd):
            return users[0]
        return None

def current_user(self, request=None) -> TypeVar('User'):
    """Retrieves the user from a request.
    """
    try:
        auth_header = self.authorization_header(request)
        b64_auth_token = self.extract_base64_authorization_header(auth_header)
        auth_token = self.decode_base64_authorization_header(b64_auth_token)
        email, password = self.extract_user_credentials(auth_token)
        return self.user_object_from_credentials(email, password)
    except ValueError as ve:
        # Handle ValueError or other exceptions
        print(f"Error in current_user: {ve}")
        return None
    except Exception as e:
        # Handle other exceptions
        print(f"Unexpected error in current_user: {e}")
        return None

