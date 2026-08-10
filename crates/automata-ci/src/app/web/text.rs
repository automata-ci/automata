pub(super) fn has_visible_display_character(value: &str) -> bool {
    value
        .chars()
        .any(|character| !character.is_whitespace() && !is_default_ignorable(character))
}

pub(super) fn is_safe_display_text(value: &str, maximum_bytes: usize) -> bool {
    value.len() <= maximum_bytes
        && has_visible_display_character(value)
        && !value.chars().any(forbidden_display_character)
}

const fn is_default_ignorable(character: char) -> bool {
    matches!(
        character,
        '\u{00ad}'
            | '\u{034f}'
            | '\u{061c}'
            | '\u{115f}'..='\u{1160}'
            | '\u{17b4}'..='\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff0}'..='\u{fff8}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e0fff}'
    )
}

pub(super) fn forbidden_display_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visible_copy_requires_more_than_whitespace_and_default_ignorables() {
        assert!(!has_visible_display_character(" \u{200b}\u{fe0f}"));
        assert!(!has_visible_display_character("\u{3164}"));
        assert!(has_visible_display_character("Deploy\u{200d}service"));
    }
}
