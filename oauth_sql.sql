# OAUTH
CREATE TABLE user_oauth
(
    user_id VARCHAR(19) NOT NULL,
    client_id VARCHAR(19) NOT NULL,
    scope TEXT,
    auth_code VARCHAR(55),
    code_created_at DATETIME,
    code_expire BIGINT(50),
    access_token VARCHAR(55),
    access_created_at DATETIME,
    access_expire BIGINT(50),
    refresh_token VARCHAR(55),
    refresh_created_at DATETIME,
    refresh_expire BIGINT(50),
    redirect_url TEXT,
    CONSTRAINT user_oauth_pk PRIMARY KEY (user_id, client_id)
);