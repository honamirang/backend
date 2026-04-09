use aes::Aes128;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use cbc::cipher::{BlockEncryptMut, KeyIvInit};
use chrono::{FixedOffset, Utc};
use quick_xml::events::Event;
use quick_xml::Reader;
use serde_json::Value;
use std::collections::HashMap;
use thiserror::Error;
use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT_LANGUAGE, CONTENT_TYPE};
use std::time::Duration;

// ─── Constants ────────────────────────────────────────────────────────────────

const HUIS_BASE: &str = "https://huis.honam.ac.kr";
const SSO_BASE: &str = "https://sso.honam.ac.kr";
const TIMEOUT: u64 = 30;
const NEXACRO_NS: &str = "http://www.nexacroplatform.com/platform/dataset";
const AES_KEY: &[u8; 16] = b"0123456789abcdef";
const AES_IV: &[u8; 16] = b"fedcba9876543210";

const USER_AGENT: &str =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
     AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36";

const CMD_DATASET_COLUMNS: &[(&str, &str, &str)] = &[
    ("TX_NAME", "STRING", "100"),
    ("TYPE", "STRING", "10"),
    ("SQL_ID", "STRING", "200"),
    ("KEY_SQL_ID", "STRING", "200"),
    ("KEY_INCREMENT", "INT", "10"),
    ("CALLBACK_SQL_ID", "STRING", "200"),
    ("INSERT_SQL_ID", "STRING", "200"),
    ("UPDATE_SQL_ID", "STRING", "200"),
    ("DELETE_SQL_ID", "STRING", "200"),
    ("SAVE_FLAG_COLUMN", "STRING", "200"),
    ("USE_INPUT", "STRING", "1"),
    ("USE_ORDER", "STRING", "1"),
    ("KEY_ZERO_LEN", "INT", "10"),
    ("BIZ_NAME", "STRING", "100"),
    ("PAGE_NO", "INT", "10"),
    ("PAGE_SIZE", "INT", "10"),
    ("READ_ALL", "STRING", "1"),
    ("EXEC_TYPE", "STRING", "2"),
    ("EXEC", "STRING", "1"),
    ("FAIL", "STRING", "1"),
    ("FAIL_MSG", "STRING", "200"),
    ("EXEC_CNT", "INT", "1"),
    ("MSG", "STRING", "200"),
];

const TERM_INPUT_COLUMNS: &[(&str, &str, &str)] = &[
    ("SADM302", "string", "255"),
    ("SADM303", "string", "255"),
    ("SADM301", "string", "255"),
];

const DAY_FIELDS: &[(&str, &str, &str, &str, &str)] = &[
    ("MON", "P1", "L1", "B1", "MON"),
    ("TUE", "P2", "L2", "B2", "TUE"),
    ("WED", "P3", "L3", "B3", "WED"),
    ("THU", "P4", "L4", "B4", "THU"),
    ("FRI", "P5", "L5", "B5", "FRI"),
    ("SAT", "P6", "L6", "B6", "SAT"),
];

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum HuisError {
    #[error("Login error: {0}")]
    Login(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("HTTP {0} for {1}")]
    HttpStatus(u16, String),

    #[error("XML parse error: {0}")]
    Xml(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, HuisError>;

// ─── HTTP layer ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct HttpResponse {
    text: String,
    url: String,
    status_code: u16,
}

impl HttpResponse {
    fn raise_for_status(&self) -> Result<()> {
        if self.status_code >= 400 {
            Err(HuisError::HttpStatus(self.status_code, self.url.clone()))
        } else {
            Ok(())
        }
    }
}

struct HttpSession {
    client: Client,
}

impl HttpSession {
    fn new(timeout: u64) -> Result<Self> {
        let client = Client::builder()
            .cookie_store(true)
            .timeout(Duration::from_secs(timeout))
            .user_agent(USER_AGENT)
            .build()?;
        Ok(Self { client })
    }

    fn get(
        &self,
        url: &str,
        headers: HeaderMap,
        params: &[(&str, &str)],
    ) -> Result<HttpResponse> {
        let resp = self
            .client
            .get(url)
            .headers(headers)
            .query(params)
            .send()?;
        Self::into_response(resp)
    }

    fn post_form(
        &self,
        url: &str,
        headers: HeaderMap,
        form: &[(&str, &str)],
    ) -> Result<HttpResponse> {
        let resp = self
            .client
            .post(url)
            .headers(headers)
            .form(form)
            .send()?;
        Self::into_response(resp)
    }

    fn post_body(
        &self,
        url: &str,
        headers: HeaderMap,
        body: String,
        content_type: &str,
    ) -> Result<HttpResponse> {
        let resp = self
            .client
            .post(url)
            .headers(headers)
            .header(CONTENT_TYPE, content_type)
            .body(body)
            .send()?;
        Self::into_response(resp)
    }

    fn into_response(resp: Response) -> Result<HttpResponse> {
        let status = resp.status().as_u16();
        let url = resp.url().to_string();
        let text = resp.text().unwrap_or_default();
        Ok(HttpResponse { text, url, status_code: status })
    }
}

// ─── Header builder ───────────────────────────────────────────────────────────

/// `extra`에 같은 헤더가 있으면 해당 값이 우선합니다.
fn build_headers(
    referer: Option<&str>,
    origin: Option<&str>,
    accept: Option<&str>,
) -> Result<HeaderMap> {
    let mut map = HeaderMap::new();

    map.insert(
        ACCEPT_LANGUAGE,
        HeaderValue::from_static("ko-KR,ko;q=0.9"),
    );
    map.insert(
        reqwest::header::ACCEPT,
        HeaderValue::from_str(
            accept.unwrap_or(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
        )
            .map_err(|e| HuisError::Login(e.to_string()))?,
    );
    if let Some(r) = referer {
        map.insert(
            reqwest::header::REFERER,
            HeaderValue::from_str(r).map_err(|e| HuisError::Login(e.to_string()))?,
        );
    }
    if let Some(o) = origin {
        map.insert(
            reqwest::header::ORIGIN,
            HeaderValue::from_str(o).map_err(|e| HuisError::Login(e.to_string()))?,
        );
    }
    Ok(map)
}

// ─── SSO redirect follower ────────────────────────────────────────────────────

fn follow_auto_forms(session: &HttpSession, mut current: HttpResponse) -> Result<HttpResponse> {
    for _ in 0..6 {
        let form = match parse_auto_form(&current.text) {
            Some(f) => f,
            None => return Ok(current),
        };
        if form.inputs.is_empty() || form.has_non_hidden_inputs {
            return Ok(current);
        }
        if !current.text.contains("submit()")
            && !current.text.contains(r#"id="form-send""#)
        {
            return Ok(current);
        }

        let action = urljoin(&current.url, &form.action);
        let origin = origin_of(&current.url);
        let headers = build_headers(Some(&current.url), Some(&origin), None)?;
        let params: Vec<(&str, &str)> = form
            .inputs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        current = if form.method == "get" {
            session.get(&action, headers, &params)?
        } else {
            session.post_form(&action, headers, &params)?
        };
        current.raise_for_status()?;
    }
    Err(HuisError::Login(
        "Too many auto-submit form hops during SSO bootstrap.".into(),
    ))
}

// ─── AES-128-CBC encryption ────────────────────────────────────────────────────

type Aes128CbcEnc = cbc::Encryptor<Aes128>;

fn encrypt_nmain_payload(plain_xml: &str) -> String {
    let mut data = plain_xml.as_bytes().to_vec();
    let rem = data.len() % 16;
    if rem != 0 {
        data.extend(std::iter::repeat(0u8).take(16 - rem));
    }
    let mut buf = data.clone();
    Aes128CbcEnc::new(AES_KEY.into(), AES_IV.into())
        .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf, data.len())
        .expect("buffer is already block-aligned");
    B64.encode(&buf)
}

// ─── XML / Dataset builders ───────────────────────────────────────────────────

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn make_dataset(
    dataset_id: &str,
    columns: &[(&str, &str, &str)],
    rows: &[HashMap<&str, &str>],
) -> String {
    let mut parts = Vec::new();
    parts.push(format!(r#"<Dataset id="{}">"#, xml_escape(dataset_id)));
    parts.push("<ColumnInfo>".to_string());
    for (id, typ, size) in columns {
        parts.push(format!(
            r#"<Column id="{}" type="{}" size="{}"/>"#,
            xml_escape(id), xml_escape(typ), xml_escape(size)
        ));
    }
    parts.push("</ColumnInfo><Rows>".to_string());
    for row in rows {
        parts.push("<Row>".to_string());
        for (key, value) in row {
            if value.is_empty() { continue; }
            parts.push(format!(
                r#"<Col id="{}">{}</Col>"#,
                xml_escape(key), xml_escape(value)
            ));
        }
        parts.push("</Row>".to_string());
    }
    parts.push("</Rows></Dataset>".to_string());
    parts.concat()
}

fn build_request_xml(parameters: &[(&str, &str)], datasets: &[String]) -> String {
    let mut parts = Vec::new();
    parts.push(r#"<?xml version="1.0" encoding="UTF-8"?>"#.to_string());
    parts.push(format!(r#"<Root xmlns="{}">"#, NEXACRO_NS));
    parts.push("<Parameters>".to_string());
    for (id, value) in parameters {
        parts.push(format!(
            r#"<Parameter id="{}">{}</Parameter>"#,
            xml_escape(id), xml_escape(value)
        ));
    }
    parts.push("</Parameters>".to_string());
    for ds in datasets {
        parts.push(ds.clone());
    }
    parts.push("</Root>".to_string());
    parts.concat()
}

// ─── Response parsers ─────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct NMainResponse {
    parameters: HashMap<String, String>,
    datasets: HashMap<String, Vec<HashMap<String, String>>>,
}

fn parse_ssv(text: &str) -> NMainResponse {
    let mut resp = NMainResponse::default();
    let mut current_dataset: Option<String> = None;
    let mut current_columns: Option<Vec<String>> = None;

    for part in text.split('\x1e') {
        if part.is_empty() || part == "SSV:UTF-8" { continue; }
        if let Some(ds_name) = part.strip_prefix("Dataset:") {
            current_dataset = Some(ds_name.to_string());
            resp.datasets.entry(ds_name.to_string()).or_insert_with(Vec::new);
            current_columns = None;
            continue;
        }
        if let Some(ds) = &current_dataset {
            if current_columns.is_none() {
                current_columns = Some(
                    part.split('\x1f')
                        .map(|f| f.split(':').next().unwrap_or(f).to_string())
                        .collect(),
                );
                continue;
            }
            if part.contains('\x1f') {
                let cols = current_columns.as_ref().unwrap();
                let values: Vec<&str> = part.split('\x1f').collect();
                let mut row = HashMap::new();
                for (i, col) in cols.iter().enumerate() {
                    let v = values.get(i).copied().unwrap_or("");
                    row.insert(col.clone(), if v == "\x03" { "".to_string() } else { v.to_string() });
                }
                resp.datasets.get_mut(ds).unwrap().push(row);
                continue;
            }
        }
        if part.contains(':') && part.contains('=') {
            let colon = part.find(':').unwrap();
            let eq = part.find('=').unwrap();
            if colon < eq {
                resp.parameters.insert(part[..colon].to_string(), part[eq + 1..].to_string());
            }
        }
    }
    resp
}

fn parse_xml_response(xml_text: &str) -> Result<NMainResponse> {
    let mut resp = NMainResponse::default();
    let mut reader = Reader::from_str(xml_text);
    reader.config_mut().trim_text(true);

    let strip_ns = |name: &[u8]| -> String {
        let s = std::str::from_utf8(name).unwrap_or("");
        s.split(':').last().unwrap_or(s).to_string()
    };

    let mut buf = Vec::new();
    let mut current_param_id: Option<String> = None;
    let mut current_dataset_id: Option<String> = None;
    let mut current_row: Option<HashMap<String, String>> = None;
    let mut current_col_id: Option<String> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let local = strip_ns(e.name().as_ref());
                match local.as_str() {
                    "Parameter" => {
                        current_param_id = e.attributes().filter_map(|a| a.ok())
                            .find(|a| strip_ns(a.key.as_ref()) == "id")
                            .map(|a| String::from_utf8_lossy(&a.value).to_string());
                    }
                    "Dataset" => {
                        let id = e.attributes().filter_map(|a| a.ok())
                            .find(|a| strip_ns(a.key.as_ref()) == "id")
                            .map(|a| String::from_utf8_lossy(&a.value).to_string());
                        if let Some(ref ds_id) = id {
                            resp.datasets.insert(ds_id.clone(), Vec::new());
                        }
                        current_dataset_id = id;
                    }
                    "Row" => { current_row = Some(HashMap::new()); }
                    "Col" => {
                        current_col_id = e.attributes().filter_map(|a| a.ok())
                            .find(|a| strip_ns(a.key.as_ref()) == "id")
                            .map(|a| String::from_utf8_lossy(&a.value).to_string());
                    }
                    _ => {}
                }
            }
            Ok(Event::End(ref e)) => {
                match strip_ns(e.name().as_ref()).as_str() {
                    "Parameter" => { current_param_id = None; }
                    "Row" => {
                        if let (Some(ds_id), Some(row)) = (&current_dataset_id, current_row.take()) {
                            if let Some(ds) = resp.datasets.get_mut(ds_id) {
                                ds.push(row);
                            }
                        }
                    }
                    "Col" => { current_col_id = None; }
                    _ => {}
                }
            }
            Ok(Event::Text(ref e)) => {
                let text = quick_xml::escape::unescape(&e.decode().unwrap_or_default())
                    .unwrap_or_default()
                    .to_string();
                if let Some(ref pid) = current_param_id {
                    resp.parameters.insert(pid.clone(), text);
                } else if let (Some(col_id), Some(row)) = (&current_col_id, &mut current_row) {
                    row.insert(col_id.clone(), text);
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(HuisError::Xml(e.to_string())),
            _ => {}
        }
        buf.clear();
    }
    Ok(resp)
}

fn parse_nmain_response(text: &str) -> Result<NMainResponse> {
    let stripped = text.trim_start();
    if stripped.starts_with("SSV:") {
        Ok(parse_ssv(text))
    } else if stripped.starts_with("<?xml") || stripped.starts_with("<Root") {
        parse_xml_response(text)
    } else {
        Err(HuisError::Protocol("Unknown NMain response format.".into()))
    }
}

// ─── NMain API call ───────────────────────────────────────────────────────────

fn post_nmain(session: &HttpSession, plain_xml: &str) -> Result<NMainResponse> {
    let encrypted = encrypt_nmain_payload(plain_xml);
    let outer_xml = format!(
        r#"<Root xmlns="{}"><Data val="{}"></Data></Root>"#,
        NEXACRO_NS, encrypted
    );

    let referer = format!("{}/HUIS/index.html", HUIS_BASE);
    let headers = build_headers(Some(&referer), Some(HUIS_BASE), Some("*/*"))?;
    let url = format!("{}/NMain", HUIS_BASE);

    let resp = session.post_body(&url, headers, outer_xml, "text/xml; charset=UTF-8")?;
    resp.raise_for_status()?;

    let parsed = parse_nmain_response(&resp.text)?;
    let error_code = parsed.parameters.get("ErrorCode").map(|s| s.as_str()).unwrap_or("0");
    if !error_code.is_empty() && error_code != "0" {
        let msg = parsed.parameters.get("ErrorMsg")
            .cloned()
            .unwrap_or_else(|| format!("NMain error {}", error_code));
        return Err(HuisError::Protocol(msg));
    }
    Ok(parsed)
}

// ─── SSO + direct login ────────────────────────────────────────────────────────

fn sso_login(user_id: &str, password: &str) -> Result<HttpSession> {
    let session = HttpSession::new(TIMEOUT)?;

    let index_url = format!("{}/HUIS/index.html", HUIS_BASE);
    let home = session.get(&index_url, build_headers(None, None, None)?, &[])?;
    home.raise_for_status()?;

    let login_jsp = format!("{}/sso/login.jsp", HUIS_BASE);
    let login_page = session.get(
        &login_jsp,
        build_headers(Some(&home.url), None, None)?,
        &[],
    )?;
    login_page.raise_for_status()?;

    let process_url = format!("{}/authentication/idpw/loginProcess", SSO_BASE);
    let form_data = [("agentId", "106"), ("id", user_id), ("pw", password)];
    let login_resp = session.post_form(
        &process_url,
        build_headers(Some(&login_page.url), Some(SSO_BASE), None)?,
        &form_data,
    )?;
    login_resp.raise_for_status()?;

    if !login_resp.text.contains("secureToken") || !login_resp.text.contains("secureSessionId") {
        return Err(HuisError::Login("SSO login failed. Check the credentials.".into()));
    }

    let current = follow_auto_forms(&session, login_resp)?;
    let current = follow_auto_forms(&session, current)?;

    if !current.text.contains("ssoSuccess=1") && !current.text.contains("NEXACROHTML.Init") {
        return Err(HuisError::Login("SSO bootstrap did not complete as expected.".into()));
    }

    Ok(session)
}

fn direct_login(session: &HttpSession, user_id: &str) -> Result<HashMap<String, String>> {
    let row: HashMap<&str, &str> = HashMap::new();
    let request_xml = build_request_xml(
        &[
            ("JSESSIONID", ""),
            ("__KSMSID__", ""),
            ("fsp_action", "AuthAction"),
            ("fsp_cmd", "login"),
            ("USER_ID", ""),
            ("USER_NAME", ""),
            ("fsp_logId", "all"),
            ("usrid", user_id),
        ],
        &[make_dataset("fsp_ds_cmd", CMD_DATASET_COLUMNS, &[row])],
    );
    let parsed = post_nmain(session, &request_xml)?;
    let users = parsed.datasets.get("ds_out").cloned().unwrap_or_default();
    if users.is_empty() {
        return Err(HuisError::Login("HUIS direct login returned no user dataset.".into()));
    }
    Ok(users.into_iter().next().unwrap())
}

// ─── Business logic ───────────────────────────────────────────────────────────

fn default_parameters<'a>(
    user_id: &'a str,
    user_name: &'a str,
    extra: &[(&'a str, &'a str)],
) -> Vec<(&'a str, &'a str)> {
    let mut params = vec![
        ("fsp_action", "nDefaultAction"),
        ("fsp_cmd", "execute"),
        ("USER_ID", user_id),
        ("USER_NAME", user_name),
        ("fsp_logId", "all"),
    ];
    params.extend_from_slice(extra);
    params
}

fn fetch_current_term(
    session: &HttpSession,
    user_id: &str,
    user_name: &str,
) -> Result<HashMap<String, String>> {
    let mut row: HashMap<&str, &str> = HashMap::new();
    row.insert("TYPE", "N");
    row.insert("SQL_ID", "a/ad/adci:adci_tadm300_S01");
    row.insert("KEY_INCREMENT", "0");
    row.insert("EXEC_TYPE", "B");

    let request_xml = build_request_xml(
        &default_parameters(user_id, user_name, &[]),
        &[make_dataset("fsp_ds_cmd", CMD_DATASET_COLUMNS, &[row])],
    );
    let parsed = post_nmain(session, &request_xml)?;
    let rows = parsed.datasets.get("ds_tadm300_out").cloned().unwrap_or_default();
    if rows.is_empty() {
        return Err(HuisError::Protocol("Current term dataset is empty.".into()));
    }
    Ok(rows.into_iter().next().unwrap())
}

fn fetch_courses(
    session: &HttpSession,
    user_id: &str,
    user_name: &str,
    year: &str,
    semester: &str,
) -> Result<Vec<HashMap<String, String>>> {
    let mut input_row: HashMap<&str, &str> = HashMap::new();
    input_row.insert("SADM302", year);
    input_row.insert("SADM303", semester);
    input_row.insert("SADM301", user_id);

    let mut cmd1: HashMap<&str, &str> = HashMap::new();
    cmd1.insert("TYPE", "N");
    cmd1.insert("SQL_ID", "a/ad/adci:adci001n_S01");
    cmd1.insert("KEY_INCREMENT", "0");
    cmd1.insert("EXEC_TYPE", "B");

    let mut cmd2: HashMap<&str, &str> = HashMap::new();
    cmd2.insert("TYPE", "N");
    cmd2.insert("SQL_ID", "a/ad/adci:adci001n_S05");
    cmd2.insert("KEY_INCREMENT", "0");
    cmd2.insert("EXEC_TYPE", "B");

    let extra = [("PARAM_USER_ID", user_id)];
    let request_xml = build_request_xml(
        &default_parameters(user_id, user_name, &extra),
        &[
            make_dataset("ds_adci001n_S01_in", TERM_INPUT_COLUMNS, &[input_row]),
            make_dataset("fsp_ds_cmd", CMD_DATASET_COLUMNS, &[cmd1, cmd2]),
        ],
    );
    let parsed = post_nmain(session, &request_xml)?;
    Ok(parsed.datasets.get("ds_adci001n_S01_out").cloned().unwrap_or_default())
}

fn fetch_grid(
    session: &HttpSession,
    user_id: &str,
    user_name: &str,
    year: &str,
    semester: &str,
) -> Result<Vec<HashMap<String, String>>> {
    let mut input_row: HashMap<&str, &str> = HashMap::new();
    input_row.insert("SADM302", year);
    input_row.insert("SADM303", semester);
    input_row.insert("SADM301", user_id);

    let mut cmd: HashMap<&str, &str> = HashMap::new();
    cmd.insert("TYPE", "N");
    cmd.insert("SQL_ID", "a/ad/adci:adci001n_S04");
    cmd.insert("KEY_INCREMENT", "0");
    cmd.insert("EXEC_TYPE", "B");

    let request_xml = build_request_xml(
        &default_parameters(user_id, user_name, &[]),
        &[
            make_dataset("ds_adci001n_S04_in", TERM_INPUT_COLUMNS, &[input_row]),
            make_dataset("fsp_ds_cmd", CMD_DATASET_COLUMNS, &[cmd]),
        ],
    );
    let parsed = post_nmain(session, &request_xml)?;
    Ok(parsed.datasets.get("ds_adci001n_S04_out").cloned().unwrap_or_default())
}

// ─── Normalisation ─────────────────────────────────────────────────────────────

fn normalize_courses(rows: &[HashMap<String, String>]) -> Vec<Value> {
    rows.iter()
        .map(|row| {
            let credits: Value = match row.get("SADT120") {
                Some(s) if !s.is_empty() => {
                    if let Ok(n) = s.parse::<i64>() { Value::Number(n.into()) }
                    else { Value::String(s.clone()) }
                }
                _ => Value::Null,
            };
            serde_json::json!({
                "course_code":      row.get("SADT206"),
                "course_name":      row.get("SADT215"),
                "section":          row.get("SADT207"),
                "professor":        row.get("SADT214"),
                "schedule_text":    row.get("SADT242"),
                "credits":          credits,
                "department":       row.get("SADT213"),
                "course_type_code": row.get("SADT119"),
                "course_type_name": row.get("SADT119_H"),
                "year":             row.get("SADT201"),
                "semester":         row.get("SADT202"),
                "semester_name":    row.get("SADT202_H"),
            })
        })
        .collect()
}

fn add_minutes(hhmm: &str, minutes: i64) -> String {
    let h: i64 = hhmm[..2].parse().unwrap_or(0);
    let m: i64 = hhmm[2..].parse().unwrap_or(0);
    let total = h * 60 + m + minutes;
    format!("{:02}:{:02}", total / 60 % 24, total % 60)
}

fn normalize_grid_rows(rows: &[HashMap<String, String>]) -> Vec<Value> {
    rows.iter()
        .map(|row| {
            let days: serde_json::Map<String, Value> = DAY_FIELDS
                .iter()
                .filter_map(|(dc, pc, lc, sc, dn)| {
                    let course_name = row.get(*dc)?.as_str();
                    if course_name.is_empty() { return None; }
                    let entry = serde_json::json!({
                        "course_name": course_name,
                        "professor":   row.get(*pc).filter(|v| !v.is_empty()),
                        "location":    row.get(*lc).filter(|v| !v.is_empty()),
                        "section":     row.get(*sc).filter(|v| !v.is_empty()),
                    });
                    Some((dn.to_string(), entry))
                })
                .collect();
            serde_json::json!({
                "period":     row.get("SADM208"),
                "time_code":  row.get("SADT810"),
                "time_label": row.get("SADT810_H"),
                "days":       days,
            })
        })
        .collect()
}

fn build_meeting_blocks(
    courses: &[Value],
    grid_rows: &[HashMap<String, String>],
) -> Vec<Value> {
    let mut course_index: HashMap<(String, Option<String>), &Value> = HashMap::new();
    for course in courses {
        if let Some(name) = course.get("course_name").and_then(|v| v.as_str()) {
            if !name.is_empty() {
                let prof = course.get("professor").and_then(|v| v.as_str()).map(|s| s.to_string());
                course_index.insert((name.to_string(), prof.clone()), course);
                course_index.entry((name.to_string(), None)).or_insert(course);
            }
        }
    }

    let mut slot_rows: Vec<HashMap<String, Value>> = Vec::new();

    for row in grid_rows {
        let start_code = match row.get("SADT810").filter(|v| !v.is_empty()) {
            Some(s) => s.clone(),
            None => continue,
        };
        let end_time = add_minutes(&start_code, 30);

        for (dc, pc, lc, sc, dn) in DAY_FIELDS {
            let course_name = match row.get(*dc).filter(|v| !v.is_empty()) {
                Some(n) => n.clone(),
                None => continue,
            };
            let professor = row.get(*pc).filter(|v| !v.is_empty()).cloned();
            let location = row.get(*lc).filter(|v| !v.is_empty()).cloned();
            let section_raw = row.get(*sc).filter(|v| !v.is_empty()).cloned();

            let match_course = course_index
                .get(&(course_name.clone(), professor.clone()))
                .or_else(|| course_index.get(&(course_name.clone(), None)));

            let section = section_raw.or_else(|| {
                match_course
                    .and_then(|c| c.get("section"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            });
            let course_code = match_course
                .and_then(|c| c.get("course_code"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let mut slot: HashMap<String, Value> = HashMap::new();
            slot.insert("day".into(), Value::String(dn.to_string()));
            slot.insert("start_code".into(), Value::String(start_code.clone()));
            slot.insert("start_time".into(), Value::String(add_minutes(&start_code, 0)));
            slot.insert("end_time".into(), Value::String(end_time.clone()));
            slot.insert("course_name".into(), Value::String(course_name));
            slot.insert("professor".into(), professor.map(Value::String).unwrap_or(Value::Null));
            slot.insert("location".into(), location.map(Value::String).unwrap_or(Value::Null));
            slot.insert("section".into(), section.map(Value::String).unwrap_or(Value::Null));
            slot.insert("course_code".into(), course_code.map(Value::String).unwrap_or(Value::Null));
            slot_rows.push(slot);
        }
    }

    slot_rows.sort_by(|a, b| {
        let day_a = a["day"].as_str().unwrap_or("");
        let day_b = b["day"].as_str().unwrap_or("");
        let sc_a = a["start_code"].as_str().unwrap_or("");
        let sc_b = b["start_code"].as_str().unwrap_or("");
        let cn_a = a["course_name"].as_str().unwrap_or("");
        let cn_b = b["course_name"].as_str().unwrap_or("");
        (day_a, sc_a, cn_a).cmp(&(day_b, sc_b, cn_b))
    });

    let mut merged: Vec<HashMap<String, Value>> = Vec::new();
    for slot in slot_rows {
        let can_merge = merged.last().is_some_and(|prev| {
            prev["day"] == slot["day"]
                && prev["course_name"] == slot["course_name"]
                && prev["professor"] == slot["professor"]
                && prev["location"] == slot["location"]
                && prev["section"] == slot["section"]
                && prev["end_time"] == slot["start_time"]
        });
        if can_merge {
            merged.last_mut().unwrap().insert("end_time".into(), slot["end_time"].clone());
        } else {
            merged.push(slot);
        }
    }

    merged.into_iter().map(|m| serde_json::json!({
        "day":         m["day"],
        "start_code":  m["start_code"],
        "start_time":  m["start_time"],
        "end_time":    m["end_time"],
        "course_name": m["course_name"],
        "professor":   m["professor"],
        "location":    m["location"],
        "section":     m["section"],
        "course_code": m["course_code"],
    })).collect()
}

// ─── Top-level fetch ──────────────────────────────────────────────────────────

pub fn fetch_timetable(user_id: &str, password: &str) -> Result<Value> {
    let session = sso_login(user_id, password)?;
    let user_info = direct_login(&session, user_id)?;

    let actual_user_id = user_info.get("USRID").cloned().unwrap_or_else(|| user_id.to_string());
    let actual_user_name = user_info.get("USRNM").cloned().unwrap_or_default();

    let term = fetch_current_term(&session, &actual_user_id, &actual_user_name)?;
    let year = term.get("SADM302").cloned().unwrap_or_default();
    let semester = term.get("SADM303").cloned().unwrap_or_default();

    let course_rows = fetch_courses(&session, &actual_user_id, &actual_user_name, &year, &semester)?;
    let grid_rows = fetch_grid(&session, &actual_user_id, &actual_user_name, &year, &semester)?;

    let courses = normalize_courses(&course_rows);
    let meeting_blocks = build_meeting_blocks(&courses, &grid_rows);
    let grid = normalize_grid_rows(&grid_rows);

    let kst = FixedOffset::east_opt(9 * 3600).unwrap();
    let fetched_at = Utc::now().with_timezone(&kst).to_rfc3339();

    Ok(serde_json::json!({
        "student": {
            "id":              actual_user_id,
            "name":            actual_user_name,
            "department_code": user_info.get("DPT_CD"),
            "department_name": user_info.get("MAIN_DPT_NM")
                                   .or_else(|| user_info.get("MAJOR_NM")),
            "grade_code":      user_info.get("GRADE_CD"),
        },
        "term": {
            "year":          year,
            "semester":      semester,
            "semester_name": term.get("SADM303_H"),
        },
        "courses":        courses,
        "meeting_blocks": meeting_blocks,
        "grid_rows":      grid,
        "fetched_at":     fetched_at,
    }))
}

// ─── HTML parsing utilities (unchanged) ──────────────────────────────────────

#[derive(Debug, Default)]
struct AutoForm {
    action: String,
    method: String,
    inputs: Vec<(String, String)>,
    has_non_hidden_inputs: bool,
}

fn parse_auto_form(html: &str) -> Option<AutoForm> {
    let mut form: Option<AutoForm> = None;
    let mut in_form = false;
    let mut rest = html;

    while let Some(lt) = rest.find('<') {
        rest = &rest[lt + 1..];
        let gt = rest.find('>').unwrap_or(rest.len());
        let tag_slice = rest[..gt].trim();
        rest = &rest[gt.min(rest.len())..];
        if tag_slice.is_empty() { continue; }

        let (tag_name, attr_str) = tag_slice
            .find(char::is_whitespace)
            .map(|sp| (&tag_slice[..sp], &tag_slice[sp + 1..]))
            .unwrap_or((tag_slice, ""));
        let tag_lower = tag_name.to_ascii_lowercase();
        let tag_lower = tag_lower.trim_start_matches('/');

        if tag_lower == "form" && form.is_none() {
            let action = attr_value(attr_str, "action").unwrap_or_default();
            let method = attr_value(attr_str, "method")
                .unwrap_or_else(|| "post".into())
                .to_ascii_lowercase();
            form = Some(AutoForm { action, method, inputs: vec![], has_non_hidden_inputs: false });
            in_form = true;
            continue;
        }
        if tag_lower == "form" && in_form { in_form = false; continue; }
        if tag_lower == "input" && in_form {
            if let Some(f) = form.as_mut() {
                let name = attr_value(attr_str, "name").unwrap_or_default();
                if name.is_empty() { continue; }
                let input_type = attr_value(attr_str, "type")
                    .unwrap_or_else(|| "text".into())
                    .to_ascii_lowercase();
                if input_type != "hidden" && input_type != "submit" {
                    f.has_non_hidden_inputs = true;
                }
                let value = attr_value(attr_str, "value").unwrap_or_default();
                f.inputs.push((name, value));
            }
        }
    }

    if let Some(f) = form.as_mut() {
        if f.action.is_empty() {
            let marker = "var sendUrl = \"";
            if let Some(idx) = html.find(marker) {
                let after = &html[idx + marker.len()..];
                if let Some(end) = after.find('"') {
                    f.action = html_unescape(&after[..end]);
                }
            }
        }
    }
    form
}

fn attr_value(attrs: &str, name: &str) -> Option<String> {
    let lower = attrs.to_ascii_lowercase();
    let pattern = format!("{}=", name.to_ascii_lowercase());
    let idx = lower.find(&pattern)?;
    let after = attrs[idx + pattern.len()..].trim_start();
    if after.starts_with('"') {
        let after = &after[1..];
        Some(html_unescape(&after[..after.find('"').unwrap_or(after.len())]))
    } else if after.starts_with('\'') {
        let after = &after[1..];
        Some(html_unescape(&after[..after.find('\'').unwrap_or(after.len())]))
    } else {
        let end = after.find(|c: char| c.is_whitespace() || c == '>').unwrap_or(after.len());
        Some(after[..end].to_string())
    }
}

fn html_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

fn urljoin(base: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        return path.to_string();
    }
    if path.starts_with('/') {
        let parsed = base.splitn(3, '/').take(2).collect::<Vec<_>>().join("/");
        return format!("{}{}", parsed, path);
    }
    if let Some(last_slash) = base.rfind('/') {
        format!("{}/{}", &base[..last_slash], path)
    } else {
        format!("{}/{}", base, path)
    }
}

fn origin_of(url: &str) -> String {
    let after_scheme = url.find("://").map(|i| i + 3).unwrap_or(0);
    let rest = &url[after_scheme..];
    let host_end = rest.find('/').unwrap_or(rest.len());
    format!("{}{}", &url[..after_scheme], &rest[..host_end])
}