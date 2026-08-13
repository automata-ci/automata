pub(crate) mod codec;
mod data;
mod encoding;
mod live;
mod model;
mod routes;
mod text;

#[cfg(test)]
pub(crate) use data::{
    EmptyWebData, RbacDirectBindingListPage, RbacDirectBindingListRequest, RbacRoleDetailRequest,
    RbacRoleListPage, RbacRoleListRequest, RbacUserDetailPage, RbacUserDetailRequest,
    RbacUserListPage, RbacUserListRequest, RbacWebDataError, RbacWebReadOutcome,
};
pub(crate) use data::{ManagementRbacWebData, RbacWebData, RequestContext, Viewer, WebData};
pub(crate) use data::{
    SetupPageAvailability, SetupPageAvailabilityError, SetupPageAvailabilityState,
};
pub(crate) use live::LiveWebData;
pub use routes::router;
pub(crate) use routes::router_with_data_and_setup_availability;
pub(crate) use routes::{
    apply_static_page_headers, error_page_response, error_page_response_with_action,
    router_with_data, router_with_data_rbac_and_management,
    router_with_data_rbac_management_and_setup_availability,
};
