use crate::{ReadAccess, TrustedServiceSid};

pub(crate) const SYSTEM_SID: &str = "S-1-5-18";
pub(crate) const ADMINISTRATORS_SID: &str = "S-1-5-32-544";

const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const FILE_WRITE_EA: u32 = 0x0000_0010;
const FILE_DELETE_CHILD: u32 = 0x0000_0040;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const DELETE: u32 = 0x0001_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_READ: u32 = 0x8000_0000;

const READ_CONTENT: u32 = FILE_READ_DATA | GENERIC_READ | GENERIC_ALL | MAXIMUM_ALLOWED;
const MUTATE: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_DELETE_CHILD
    | FILE_WRITE_ATTRIBUTES
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | MAXIMUM_ALLOWED
    | GENERIC_ALL
    | GENERIC_WRITE;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AceObservation {
    pub(crate) sid: String,
    pub(crate) access_allowed: bool,
    pub(crate) flags: u8,
    pub(crate) mask: u32,
}

pub(crate) fn descriptor_is_trusted(
    owner: &str,
    current_sid: &str,
    service_sids: &[TrustedServiceSid],
    access: ReadAccess,
    protected: bool,
    aces: &[AceObservation],
) -> bool {
    if !protected
        || aces.is_empty()
        || aces.len() > 16
        || !(owner == current_sid || service_sids.iter().any(|sid| sid.as_str() == owner))
    {
        return false;
    }

    let mut current_can_read = false;
    for ace in aces {
        if !ace.access_allowed || ace.flags != 0 || ace.mask == 0 {
            return false;
        }
        let trusted = ace.sid == current_sid
            || ace.sid == SYSTEM_SID
            || ace.sid == ADMINISTRATORS_SID
            || service_sids.iter().any(|sid| sid.as_str() == ace.sid);
        if !trusted
            && (access == ReadAccess::Private
                || ace.mask & MUTATE != 0
                || ace.mask & READ_CONTENT == 0)
        {
            return false;
        }
        current_can_read |= ace.sid == current_sid && ace.mask & READ_CONTENT != 0;
    }
    current_can_read
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "S-1-5-21-1-2-3-1001";
    const OTHER: &str = "S-1-5-21-1-2-3-1002";
    const SERVICE: &str = "S-1-5-80-1-2-3-4-5";

    fn allow(sid: &str, mask: u32) -> AceObservation {
        AceObservation {
            sid: sid.to_owned(),
            access_allowed: true,
            flags: 0,
            mask,
        }
    }

    #[test]
    fn private_files_require_a_protected_exact_trustee_set() {
        let exact = [allow(USER, FILE_READ_DATA | FILE_WRITE_DATA)];
        assert!(descriptor_is_trusted(
            USER,
            USER,
            &[],
            ReadAccess::Private,
            true,
            &exact,
        ));
        assert!(!descriptor_is_trusted(
            USER,
            USER,
            &[],
            ReadAccess::Private,
            false,
            &exact,
        ));
        let broader = [exact[0].clone(), allow(OTHER, FILE_READ_DATA)];
        assert!(!descriptor_is_trusted(
            USER,
            USER,
            &[],
            ReadAccess::Private,
            true,
            &broader,
        ));
    }

    #[test]
    fn public_read_never_allows_an_untrusted_mutator() {
        let readable = [allow(USER, FILE_READ_DATA), allow(OTHER, FILE_READ_DATA)];
        assert!(descriptor_is_trusted(
            USER,
            USER,
            &[],
            ReadAccess::PublicRead,
            true,
            &readable,
        ));
        let writable = [
            allow(USER, FILE_READ_DATA),
            allow(OTHER, FILE_READ_DATA | FILE_WRITE_DATA),
        ];
        assert!(!descriptor_is_trusted(
            USER,
            USER,
            &[],
            ReadAccess::PublicRead,
            true,
            &writable,
        ));
    }

    #[test]
    fn approved_service_owner_still_requires_current_reader_access() {
        let service = TrustedServiceSid::new(SERVICE).expect("canonical service SID");
        assert!(descriptor_is_trusted(
            SERVICE,
            USER,
            std::slice::from_ref(&service),
            ReadAccess::Private,
            true,
            &[allow(USER, FILE_READ_DATA), allow(SERVICE, GENERIC_ALL)],
        ));
        assert!(!descriptor_is_trusted(
            SERVICE,
            USER,
            &[service],
            ReadAccess::Private,
            true,
            &[allow(SERVICE, GENERIC_ALL)],
        ));
    }

    #[test]
    fn inherited_denied_empty_and_zero_mask_aces_fail_closed() {
        for ace in [
            AceObservation {
                sid: USER.to_owned(),
                access_allowed: true,
                flags: 0x10,
                mask: FILE_READ_DATA,
            },
            AceObservation {
                sid: USER.to_owned(),
                access_allowed: false,
                flags: 0,
                mask: FILE_READ_DATA,
            },
            allow(USER, 0),
        ] {
            assert!(!descriptor_is_trusted(
                USER,
                USER,
                &[],
                ReadAccess::Private,
                true,
                &[ace],
            ));
        }
        assert!(!descriptor_is_trusted(
            USER,
            USER,
            &[],
            ReadAccess::Private,
            true,
            &[],
        ));
    }

    #[test]
    fn trusted_service_sid_parser_is_exact() {
        assert!(TrustedServiceSid::new(SERVICE).is_ok());
        for invalid in [
            "S-1-5-18",
            "S-1-5-80-1-2-3-4",
            "S-1-5-80-1-2-3-4-5-6",
            "S-1-5-80-01-2-3-4-5",
            "S-1-5-80-a-2-3-4-5",
        ] {
            assert!(TrustedServiceSid::new(invalid).is_err(), "{invalid}");
        }
        assert!(TrustedServiceSid::new("S-1-5-80-0-2-3-4-5").is_ok());
    }
}
