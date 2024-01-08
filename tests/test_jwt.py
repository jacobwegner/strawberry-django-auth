import time
from datetime import timedelta

import pytest
from gqlauth.core.exceptions import TokenExpired
from gqlauth.jwt.types_ import TokenType
from gqlauth.models import RefreshToken


def test_expired_refresh_token(db_verified_user_status, app_settings, override_gqlauth):
    with override_gqlauth(name="JWT_REFRESH_EXPIRATION_DELTA", replace=timedelta(seconds=0.1)):
        rt = RefreshToken.from_user(db_verified_user_status.user.obj)
        assert not rt.is_expired_()
        time.sleep(1)
        assert rt.is_expired_()
    assert app_settings.JWT_REFRESH_EXPIRATION_DELTA


def test_token_expired(db_verified_user_status, app_settings, override_gqlauth):
    with override_gqlauth(app_settings.JWT_EXPIRATION_DELTA, timedelta(seconds=1)):
        initial_token = TokenType.from_user(db_verified_user_status.user.obj)
        token = TokenType.from_token(initial_token.token)
        assert not token.is_expired()
        time.sleep(2)
        assert token.is_expired()
        with pytest.raises(TokenExpired):
            TokenType.from_token(token.token)
    assert app_settings.JWT_EXPIRATION_DELTA
