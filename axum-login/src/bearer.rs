use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::{
    backend::{AuthUser, UserId},
    BearerAuthnBackend,
};

/// An error type which maps session and backend errors.
#[derive(thiserror::Error)]
pub enum Error<Backend: BearerAuthnBackend> {
    /// A mapping to `Backend::Error`.
    #[error(transparent)]
    Backend(Backend::Error),
}

impl<Backend: BearerAuthnBackend> Debug for Error<Backend> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Backend(err) => write!(f, "{:?}", err)?,
        };

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Data<UserId> {
    user_id: Option<UserId>,
    auth_hash: Option<Vec<u8>>,
}

impl<UserId: Clone> Default for Data<UserId> {
    fn default() -> Self {
        Self {
            user_id: None,
            auth_hash: None,
        }
    }
}

/// A specialized session for identification, authentication, and authorization
/// of users associated with a backend.
///
/// The session is generic over some backend which implements [`AuthnBackend`].
/// The backend may also implement [`AuthzBackend`](crate::AuthzBackend),
/// in which case it will also supply authorization methods.
///
/// Methods for authenticating the session and logging a user in are provided.
///
/// Generally this session will be used in the context of some authentication
/// workflow, for example via a frontend login form. There a user would provide
/// their credentials, such as username and password, and via the backend
/// the session would authenticate those credentials.
///
/// Once the supplied credentials have been authenticated, a user will be
/// returned. In the case the credentials are invalid, no user will be returned.
/// When we do have a user, it's then possible to set the state of the session
/// so that the user is logged in.
#[derive(Debug, Clone)]
pub struct AuthBearer<Backend: BearerAuthnBackend> {
    /// The user associated by the backend. `None` when not logged in.
    pub principal: Option<Backend::Principal>,

    /// The authentication and authorization backend.
    pub backend: Backend,
}

impl<Backend: BearerAuthnBackend> AuthBearer<Backend> {
    /// Verifies the provided credentials via the backend returning the
    /// authenticated user if valid and otherwise `None`.
    #[tracing::instrument(level = "debug", skip_all, fields(principal), ret, err)]
    pub async fn authenticate(
        &self,
        bearer: Backend::Bearer,
    ) -> Result<Option<Backend::Principal>, Error<Backend>> {
        let result = self
            .backend
            .authenticate(bearer)
            .await
            .map_err(Error::Backend);

        if let Ok(Some(ref principal)) = result {
            tracing::Span::current().record("principal", principal.to_string());
        }

        result
    }
}
