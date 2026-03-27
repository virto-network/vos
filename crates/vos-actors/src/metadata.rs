//! Actor message metadata — static descriptors for introspection.

pub struct FieldMeta {
    pub name: &'static str,
    pub ty: &'static str,
}

pub struct MessageMeta {
    pub name: &'static str,
    pub is_query: bool,
    pub fields: &'static [FieldMeta],
}

pub struct ActorMeta {
    pub actor_name: &'static str,
    pub messages: &'static [MessageMeta],
}
