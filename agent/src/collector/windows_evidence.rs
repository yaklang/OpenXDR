//! Windows Event Log 证据归一化；不依赖 WinAPI，可在 Linux 上跑相同解析回归。
use serde_json::{Value, json};

fn data(xml: &str, key: &str) -> Option<String> {
    let single = format!("Name='{key}'>");
    let double = format!("Name=\"{key}\">");
    let needle = if xml.contains(&single) {
        single
    } else {
        double
    };
    let rest = &xml[xml.find(&needle)? + needle.len()..];
    let value = &rest[..rest.find("</Data>")?];
    if value.len() > 65536 {
        return None;
    }
    Some(
        value
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&")
            .trim()
            .to_owned(),
    )
}

pub fn authentication_context(xml: &str) -> Value {
    let mut value = json!({});
    for (input, output) in [
        ("AuthenticationPackageName", "authentication_package"),
        ("LogonProcessName", "logon_process"),
        ("WorkstationName", "workstation_name"),
        ("LmPackageName", "ntlm_package"),
        ("KeyLength", "authentication_key_length"),
    ] {
        if let Some(text) = data(xml, input)
            && !text.is_empty()
            && text != "-"
        {
            value[output] = text.into();
        }
    }
    value
}

pub fn sysmon(xml: &str) -> Option<Value> {
    if xml.len() > 1_048_576
        || !(xml.contains("Name='Microsoft-Windows-Sysmon'")
            || xml.contains("Name=\"Microsoft-Windows-Sysmon\""))
    {
        return None;
    }
    let start = xml.find("<EventID")? + "<EventID".len();
    let rest = &xml[start + xml[start..].find('>')? + 1..];
    let id: u32 = rest[..rest.find("</EventID>")?].trim().parse().ok()?;
    if !matches!(id, 8 | 10 | 25) {
        return None;
    }
    let mut value = json!({"event_id":id,"provider":"Microsoft-Windows-Sysmon"});
    for (input, output) in [
        ("SourceImage", "source_image"),
        ("TargetImage", "target_image"),
        ("SourceProcessGUID", "source_process_guid"),
        ("TargetProcessGUID", "target_process_guid"),
        ("Image", "image"),
        ("Type", "tamper_type"),
        ("StartModule", "start_module"),
        ("StartFunction", "start_function"),
        ("UtcTime", "utc_time"),
    ] {
        if let Some(text) = data(xml, input)
            && !text.is_empty()
            && text != "-"
        {
            value[output] = text.into();
        }
    }
    for (input, output) in [
        ("SourceProcessId", "source_pid"),
        ("TargetProcessId", "target_pid"),
        ("ProcessId", "pid"),
    ] {
        if let Some(number) = data(xml, input).and_then(|v| v.parse::<u32>().ok()) {
            value[output] = number.into();
        }
    }
    if id == 10 {
        let access = data(xml, "GrantedAccess")?;
        let digits = access
            .strip_prefix("0x")
            .or_else(|| access.strip_prefix("0X"))?;
        value["granted_access"] = format!("0x{:x}", u32::from_str_radix(digits, 16).ok()?).into();
    }
    let required = if id == 25 {
        vec!["image", "tamper_type"]
    } else {
        vec!["source_image", "target_image"]
    };
    if required.iter().any(|k| value.get(*k).is_none()) {
        return None;
    }
    // 私有活动编号，不伪装成进程启动，避免污染现有进程启动类规则和身份归因。
    Some(json!({"activity_id":100+id,"sysmon":value}))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event(id: u32, fields: &str) -> String {
        format!(
            "<Event><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>{id}</EventID></System><EventData>{fields}</EventData></Event>"
        )
    }
    #[test]
    fn sysmon_access_preserves_evidence_and_normalizes_mask() {
        let e = event(
            10,
            "<Data Name='SourceImage'>C:\\a&amp;b.exe</Data><Data Name='TargetImage'>C:\\Windows\\lsass.exe</Data><Data Name='GrantedAccess'>0X001010</Data><Data Name='SourceProcessId'>123</Data>",
        );
        let v = sysmon(&e).unwrap();
        assert_eq!(v["sysmon"]["granted_access"], "0x1010");
        assert_eq!(v["sysmon"]["source_image"], "C:\\a&b.exe");
        assert_eq!(v["sysmon"]["source_pid"], 123);
        assert_ne!(v["activity_id"], 1);
        assert!(sysmon(&e.replace("Microsoft-Windows-Sysmon", "Other")).is_none());
        assert!(sysmon(&e.replace("0X001010", "bad")).is_none());
        assert!(sysmon(&event(10, "")).is_none());
        assert!(sysmon(&event(1, "")).is_none());
    }
    #[test]
    fn remote_thread_and_image_replacement_are_distinct() {
        assert_eq!(sysmon(&event(8,"<Data Name='SourceImage'>C:\\a.exe</Data><Data Name='TargetImage'>C:\\svchost.exe</Data>")).unwrap()["sysmon"]["event_id"],8);
        let v = sysmon(&event(
            25,
            "<Data Name=\"Image\">C:\\a.exe</Data><Data Name=\"Type\">Image is replaced</Data>",
        ))
        .unwrap();
        assert_eq!(v["sysmon"]["tamper_type"], "Image is replaced");
    }
    #[test]
    fn authentication_fields_are_not_invented() {
        assert_eq!(authentication_context("<Event/>"), json!({}));
        let v = authentication_context(
            "<Data Name='AuthenticationPackageName'>NTLM</Data><Data Name='LogonProcessName'>NtLmSsp </Data><Data Name='WorkstationName'>WS01</Data><Data Name='LmPackageName'>-</Data>",
        );
        assert_eq!(v["authentication_package"], "NTLM");
        assert_eq!(v["logon_process"], "NtLmSsp");
        assert_eq!(v["workstation_name"], "WS01");
        assert!(v.get("ntlm_package").is_none());
    }
}
