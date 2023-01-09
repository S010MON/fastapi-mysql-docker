class Settings:
    # General Settings
    PROJECT_NAME: str = "Auth Api"
    PROJECT_VERSION: str = "1.0.0"

    # Security Settings
    SECRET_KEY: str = "2ee8fcb254553242b962ddad393d499d50dc0397623f7b1b0b1f4a801072b573"  # SECRET_KEY: str = os.getenv("SECRET_KEY")
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINS = 30
    MAX_PASSWORD_ATTEMTPS = 3

    # Testing Settings
    TESTING = False
    PRODUCTION = False
    TEST_USERNAME = "root"
    TEST_PASSWORD = "password"


settings = Settings()