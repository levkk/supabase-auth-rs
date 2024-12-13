//! Supabase Auth client.
//!
//! # Features
//!
//! - Sign in anonymously
//! - Refresh JWT token
//!
use chrono::{DateTime, Utc};
use reqwest::RequestBuilder;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Supabase Auth user.
///
/// See <https://supabase.com/docs/reference/javascript/auth-getuser> for fields documentation.
#[derive(Serialize, Deserialize, Clone)]
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
#[derive(Serialize, Deserialize, Clone)]
pub struct Signup {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub expires_at: i64,
    pub refresh_token: String,
    pub user: User,
}

/// Error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Http(#[from] reqwest::Error),
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

    fn request(&self, action: &str) -> RequestBuilder {
        reqwest::Client::new()
            .post(format!("{}/auth/v1/{}", &self.endpoint, action))
            .query(&[("apikey", &self.token)])
    }

    /// Create an anonymous user.
    pub async fn sign_in_anonymously(&self) -> Result<Signup, Error> {
        let req = self.request("signup");
        let res = req
            .json(&serde_json::json!({"data": {}}))
            .send()
            .await?
            .json::<Signup>()
            .await?;

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
