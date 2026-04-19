use std::{
    cell::LazyCell,
    collections::{HashMap, hash_map},
};

use derive_more::{Deref, DerefMut, From, Into};
use http::uri::{Authority, PathAndQuery, Scheme};

use super::{Bind, BindConflictError, BindHost};
use crate::dquic::qinterface::bind_uri::BindUri;

/// A collection of [`Bind`] patterns, typically populated from CLI arguments.
#[derive(Debug, Clone, PartialEq, Eq, Deref, DerefMut, From, Into)]
pub struct Binds {
    /// Bind patterns
    binds: Vec<Bind>,
}

impl Binds {
    /// Create a new [`Binds`] from a list of [`Bind`] patterns.
    pub fn new(binds: Vec<Bind>) -> Self {
        Self { binds }
    }

    /// Expand all contained [`Bind`] patterns into concrete [`BindUri`]s,
    /// checking for conflicting path-and-query on the same target.
    ///
    /// Two expanded URIs are considered "the same target" when their
    /// scheme and authority (IP + port, or family + NIC + port) are
    /// identical.  If such a pair carries different path-and-query
    /// values, a [`BindConflictError`] is returned.
    ///
    /// Duplicate URIs (same target *and* same path-and-query) are
    /// silently deduplicated.
    #[allow(clippy::result_large_err)]
    pub fn to_bind_uris<'a, I>(
        &'a self,
        interfaces: I,
    ) -> Result<Vec<BindUri>, Box<BindConflictError>>
    where
        I: IntoIterator<Item = &'a str> + Clone,
    {
        let mut seen: HashMap<(Scheme, Authority), Option<PathAndQuery>> = HashMap::new();
        let mut bind_uris = Vec::new();

        let mut push_bind_uri = |bind_uri: BindUri| {
            let inner = bind_uri.as_uri();
            let key = (
                inner.scheme().expect("BindUri always has a scheme").clone(),
                inner
                    .authority()
                    .expect("BindUri always has an authority")
                    .clone(),
            );
            let path_and_query = inner.path_and_query().cloned();
            // Normalize a bare `/` to `None` for consistent conflict semantics.
            let path_and_query =
                path_and_query.and_then(|pq| if pq.as_str() == "/" { None } else { Some(pq) });

            match seen.entry(key) {
                hash_map::Entry::Occupied(entry) => {
                    if *entry.get() != path_and_query {
                        let (scheme, authority) = entry.key();
                        return Err(Box::new(BindConflictError {
                            scheme: scheme.clone(),
                            authority: authority.clone(),
                            existing: entry.get().clone(),
                            incoming: path_and_query,
                        }));
                    }
                    Ok(())
                }
                hash_map::Entry::Vacant(entry) => {
                    entry.insert(path_and_query.clone());
                    bind_uris.push(bind_uri);
                    Ok(())
                }
            }
        };

        let bind_uri_templates =
            self.iter()
                .try_fold(Vec::with_capacity(self.len()), |mut templates, bind| {
                    match bind.host {
                        BindHost::Ip { addr, .. } => {
                            let template = bind.bind_uri_template();
                            let port = bind.effective_port();
                            let authority = format!("{addr}:{port}").parse();
                            if let Some(bind_uri) = authority.ok().and_then(template) {
                                push_bind_uri(bind_uri)?;
                            }
                        }
                        BindHost::Glob { .. } | BindHost::Exact { .. } => {
                            let template = LazyCell::new(|| bind.bind_uri_template());
                            templates.push((bind, template))
                        }
                    }
                    Ok::<_, Box<BindConflictError>>(templates)
                })?;

        interfaces
            .into_iter()
            .flat_map(|interface| {
                bind_uri_templates.iter().flat_map(|(bind, template)| {
                    #[allow(clippy::redundant_closure)]
                    bind.bind_hosts_for_interface(interface)
                        .flat_map(|authority| template(authority))
                })
            })
            .try_for_each(push_bind_uri)?;

        Ok(bind_uris)
    }
}
