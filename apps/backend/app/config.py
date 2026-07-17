from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "sentinelai-threat-detection"
    database_url: str = "sqlite:///./sentinelai.db"
    jwt_secret: str = "dev-only-change-me"
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 60 * 12
    openai_api_key: str | None = None
    # Support both common local development origins. Browsers treat localhost
    # and 127.0.0.1 as distinct origins, so allowing only one prevents the
    # dashboard's authenticated CSV upload from reaching the API.
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
