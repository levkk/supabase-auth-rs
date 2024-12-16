//! Supabase Auth client.
//!
//! # Features
//!
//! - Sign in anonymously
//! - Refresh JWT token
//!
use chrono::{DateTime, Utc};
use postgrest::Postgrest;
use reqwest::RequestBuilder;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::from_str;
use uuid::Uuid;

/// Supabase Auth user.
///
/// See <https://supabase.com/docs/reference/javascript/auth-getuser> for fields documentation.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    pub id: Uuid,
    pub aud: String,
    pub role: String,
    pub email: String,
    pub phone: String,
    pub last_sign_in_at: DateTime<Utc>,
    pub app_metadata: serde_json::Value,
    pub user_metadata: serde_json::Value,
    pub identities: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Supabase Auth sign up response.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Signup {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub expires_at: i64,
    pub refresh_token: String,
    pub user: User,
}

/// Supabase signup options.
#[derive(Clone, Debug)]
pub struct AnonymousSigninOptions {
    /// Captcha token.
    pub captcha_token: Option<String>,
    /// Metadata.
    pub data: serde_json::Value,
}

impl AnonymousSigninOptions {
    fn captcha_token(&self) -> serde_json::Value {
        match self.captcha_token.as_ref() {
            Some(token) => serde_json::Value::String(token.clone()),
            None => serde_json::Value::Null,
        }
    }
}

impl Default for AnonymousSigninOptions {
    fn default() -> Self {
        Self {
            captcha_token: None,
            data: serde_json::json!({}),
        }
    }
}

/// Error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Http(#[from] reqwest::Error),

    #[error("{0}")]
    Json(#[from] serde_json::Error),

    #[error("supabase not configured")]
    NotConfigured,
}

/// Supabase Auth HTTP client.
#[derive(Clone)]
pub struct Client {
    token: String,
    endpoint: String,
}

impl Client {
    /// Create new Supabase Auth client.
    ///
    /// # Arguments
    ///
    /// - `endpoint`: Project API endpoint.
    /// - `token`: Project authentication token.
    ///
    /// # Note
    ///
    /// Make sure the project endpoint does not contain a trailing slash.
    pub fn new(endpoint: impl ToString, token: impl ToString) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            token: token.to_string(),
        }
    }

    /// Create new Supabase Auth client from environment.
    pub fn new_from_env() -> Self {
        Self::new(
            option_env!("SUPABASE_ENDPOINT").expect("SUPABASE_ENDPOINT not set"),
            option_env!("SUPABASE_TOKEN").expect("SUPABASE_TOKEN not set"),
        )
        .check()
        .unwrap()
    }

    fn check(self) -> Result<Self, Error> {
        if self.endpoint.is_empty() || self.token.is_empty() {
            return Err(Error::NotConfigured);
        }

        Ok(self)
    }

    /// Get database handle.
    pub fn db(&self) -> Postgrest {
        Postgrest::new(format!("{}/rest/v1", &self.endpoint)).insert_header("apikey", &self.token)
    }

    fn request(&self, action: &str) -> RequestBuilder {
        reqwest::Client::new()
            .post(format!("{}/auth/v1/{}", &self.endpoint, action))
            .query(&[("apikey", &self.token)])
    }

    /// Create an anonymous user.
    pub async fn sign_in_anonymously(
        &self,
        options: &AnonymousSigninOptions,
        name: &str,
    ) -> Result<Signup, Error> {
        let req = self.request("signup");
        let json = serde_json::json!({
            "data": options.data,
            "gotrue_meta_security": {
                "captcha_token": options.captcha_token(),
            }

        });
        let res = req.json(&json).send().await?.json::<Signup>().await?;

        LocalStorage::set(name, serde_json::to_string(&res).unwrap());

        Ok(res)
    }
}

impl Signup {
    /// Refresh the JWT token.
    ///
    /// # Arguments
    ///
    /// - `client`: Supabase Auth client.
    ///
    pub async fn refresh_token(&self, client: &Client) -> Result<Self, Error> {
        let res = client
            .request("token")
            .query(&[("grant_type", "refresh_token")])
            .json(&serde_json::json!({
                "refresh_token": &self.refresh_token,
            }))
            .send()
            .await?
            .json::<Signup>()
            .await?;
        Ok(res)
    }

    /// Check if this JWT token expired.
    pub fn expired(&self) -> bool {
        let now = Utc::now().timestamp();
        self.expires_at < now
    }

    /// Fetch and refresh auth.
    pub async fn fetch(name: &str) -> Result<Option<Self>, Error> {
        if let Some(auth) = LocalStorage::get(name) {
            let auth: Signup = from_str(&auth)?;

            if auth.expired() {
                let client = Client::new_from_env();
                let auth = auth.refresh_token(&client).await?;

                LocalStorage::set(name, serde_json::to_string(&auth).unwrap());

                Ok(Some(auth))
            } else {
                Ok(Some(auth))
            }
        } else {
            Ok(None)
        }
    }

    /// Save session in localStorage.
    pub fn save(&self, name: &str) {
        LocalStorage::set(name, serde_json::to_string(self).unwrap())
    }

    /// Validate session before using.
    pub async fn session(self) -> Result<(Self, bool), Error> {
        if self.expired() {
            let client = Client::new_from_env();
            Ok((self.refresh_token(&client).await?, true))
        } else {
            Ok((self, false))
        }
    }

    /// Get authenticated database handle.
    pub fn db(&self, table: &str) -> postgrest::Builder {
        Client::new_from_env()
            .db()
            .from(table)
            .auth(&self.access_token)
    }
}

impl User {
    /// Update user attributes.
    ///
    /// See <https://supabase.com/docs/reference/javascript/auth-updateuser> for allowed attributes.
    pub async fn update(
        self,
        client: &Client,
        signup: &Signup,
        attributes: &serde_json::Value,
    ) -> Result<Self, Error> {
        let res = reqwest::Client::new()
            .put(&format!("{}/auth/v1/user", &client.endpoint))
            .query(&[("apikey", &client.token)])
            .bearer_auth(&signup.access_token)
            .json(attributes)
            .send()
            .await?
            .json::<User>()
            .await?;
        Ok(res)
    }

    /// Fetch the user.
    pub async fn get(client: &Client, signup: &Signup) -> Result<Self, Error> {
        let res = reqwest::Client::new()
            .get(&format!("{}/auth/v1/user", &client.endpoint))
            .query(&[("apikey", &client.token)])
            .bearer_auth(&signup.access_token)
            .send()
            .await?
            .json::<User>()
            .await?;
        Ok(res)
    }

    /// Make sure client has a pet identifier.
    pub async fn sync(self, session: &Signup, pet_uuid: String) -> Result<Self, Error> {
        let mut replace = false;

        if let Some(data) = self.user_metadata.as_object() {
            if let Some(stored) = data.get("pet_uuid") {
                if let Some(stored_str) = stored.as_str() {
                    if stored_str != pet_uuid {
                        replace = true;
                    }
                }
            } else {
                replace = true;
            }
        }

        if replace {
            let user = self
                .update(
                    &Client::new_from_env(),
                    session,
                    &serde_json::json!({
                        "data": {
                            "pet_uuid": pet_uuid,
                        }
                    }),
                )
                .await?;

            Ok(user)
        } else {
            Ok(self)
        }
    }
}

/// localStorage wrapper.
pub struct LocalStorage;

impl LocalStorage {
    /// Get handle to localStorage.
    pub fn handle() -> web_sys::Storage {
        web_sys::window().unwrap().local_storage().unwrap().unwrap()
    }

    /// Set item.
    pub fn get(name: &str) -> Option<String> {
        let handle = Self::handle();

        handle.get_item(name).unwrap()
    }

    /// Get item.
    pub fn set(name: &str, value: impl ToString) {
        let handle = Self::handle();

        handle.set_item(name, &value.to_string()).unwrap();
    }
}

/// Get localStorage handle.
pub fn local_storage() -> web_sys::Storage {
    web_sys::window().unwrap().local_storage().unwrap().unwrap()
}

/// PostgREST query.
pub struct Query {
    builder: postgrest::Builder,
}

impl Query {
    pub fn new(builder: postgrest::Builder) -> Self {
        Self { builder }
    }

    /// Fetch result and convert to Rust struct.
    pub async fn fetch_all<T: DeserializeOwned + Clone>(self) -> Result<Vec<T>, Error> {
        let result = self.builder.execute().await.unwrap().text().await.unwrap();

        Ok(from_str::<Vec<T>>(&result)?)
    }

    /// Fetch result and convert to Rust struct.
    pub async fn fetch_one<T: DeserializeOwned + Clone>(self) -> Result<Option<T>, Error> {
        let result = self.fetch_all().await?;

        Ok(result.first().cloned())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::Datelike;

    #[test]
    fn test_user() {
        let user = r#"{"id":"66e09d42-ad07-4c0e-ae55-23b7699bfe28","aud":"authenticated","role":"authenticated","email":"","phone":"","last_sign_in_at":"2024-12-13T08:50:43.658617Z","app_metadata":{},"user_metadata":{},"identities":[],"created_at":"2024-12-13T08:50:43.648103Z","updated_at":"2024-12-13T08:57:27.559606Z","is_anonymous":true}"#;

        let user = serde_json::from_str::<User>(user).unwrap();

        assert_eq!(
            user.id,
            Uuid::parse_str("66e09d42-ad07-4c0e-ae55-23b7699bfe28").unwrap()
        );
        assert_eq!(user.created_at.day(), 13);
    }

    #[test]
    fn test_signup() {
        let res = r#"{"access_token":"eyJhbGciOiJIUzI1NiIsImtpZCI6IkljL3lYcDh2Qk1QTVEyeDAiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2hma2Z5YXJzanh3b2Nwc2NpeGNqLnN1cGFiYXNlLmNvL2F1dGgvdjEiLCJzdWIiOiI2NmUwOWQ0Mi1hZDA3LTRjMGUtYWU1NS0yM2I3Njk5YmZlMjgiLCJhdWQiOiJhdXRoZW50aWNhdGVkIiwiZXhwIjoxNzM0MDgzODYxLCJpYXQiOjE3MzQwODAyNjEsImVtYWlsIjoiIiwicGhvbmUiOiIiLCJhcHBfbWV0YWRhdGEiOnt9LCJ1c2VyX21ldGFkYXRhIjp7fSwicm9sZSI6ImF1dGhlbnRpY2F0ZWQiLCJhYWwiOiJhYWwxIiwiYW1yIjpbeyJtZXRob2QiOiJhbm9ueW1vdXMiLCJ0aW1lc3RhbXAiOjE3MzQwNzk4NDN9XSwic2Vzc2lvbl9pZCI6ImQ2MjU5NTVjLTEzNjktNGFiYi05ZmYxLWVlNWQyNWE3YzYyNiIsImlzX2Fub255bW91cyI6dHJ1ZX0.BBSI_WluBmmeNmpbfX3wIgyf9ZVrb-YMult6QqxdgIc","token_type":"bearer","expires_in":3600,"expires_at":1734083861,"refresh_token":"9G8N4PQLSicOyQR2aApkgA","user":{"id":"66e09d42-ad07-4c0e-ae55-23b7699bfe28","aud":"authenticated","role":"authenticated","email":"","phone":"","last_sign_in_at":"2024-12-13T08:50:43.658617Z","app_metadata":{},"user_metadata":{},"identities":[],"created_at":"2024-12-13T08:50:43.648103Z","updated_at":"2024-12-13T08:57:27.559606Z","is_anonymous":true}}"#;
        let res = serde_json::from_str::<Signup>(res).unwrap();
        assert_eq!(res.refresh_token, "9G8N4PQLSicOyQR2aApkgA");
    }
}
