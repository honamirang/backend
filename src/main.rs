#![deny(unused_mut)]
#![deny(unused_imports)]

mod fetch;

use axum::{response::Html, routing::get, Json, Router, http::Method, routing::any};
use tower_http::cors::{Any, CorsLayer};
use tokio::net::TcpListener;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use crate::fetch::fetch_timetable;

#[derive(Deserialize)]
struct Login {
    identifier: String,
    password: String,
}

#[derive(Deserialize, Serialize)]
struct Root {
    // 학생 정보
    student: Student,

    // 학기 정보
    term: Term,

    // 시간표 전체 (시간 단위로 나뉜 리스트)
    grid_rows: Vec<GridRow>,

    // 데이터 가져온 시간 (ISO datetime 문자열)
    fetched_at: String
}

#[derive(Deserialize, Serialize)]
struct Student {
    // 학번
    id: String,

    // 이름
    name: String,

    // 학과 코드
    department_code: String
}

#[derive(Deserialize, Serialize)]
struct Term {
    // 연도 (예: 2026)
    year: String,

    // 학기 (예: 1학기)
    semester: String
}

#[derive(Deserialize, Serialize)]
struct GridRow {
    // 교시 (01, 02 ...)
    period: String,

    // 시간 코드 (예: 0900, 0930)
    time_code: String,

    // 사람이 보기 좋은 시간 문자열 (예: "09 : 00")
    time_label: String,

    /**
     * 요일별 수업 정보
     * key: "MON", "TUE", "WED" ...
     * value: 해당 시간에 수업이 있으면 Course, 없으면 key 자체가 없음
     */
    days: Map<String, Value>
}

#[derive(Deserialize, Serialize)]
struct Course {
    // 과목명
    course_name: String,

    // 교수명
    professor: String,

    // 강의실
    location: String,

    // 분반
    section: String
}

#[tokio::main]
async fn main() {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([]);
    // build our application with a route
    let app = Router::new()
        .route("/", any(handler))
        .route("/sans", get(sans_handler))
        .route("/fetch", get(fetch_handler))
        .layer(cors);

    // run it
    let listener = TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await;
}

async fn handler(method: Method) -> Json<&'static str> {
    Json("{ hello_world: \"Hello, world\" }")
}

async fn sans_handler() -> Html<&'static str> {
    Html("<h1>Sans</h1>")
}

async fn fetch_handler(Json(login): Json<Login>) -> Json<String> {
    //Json(fetch_timetable(&login.identifier, &login.password).unwrap_or_else(|error| error.to_string()).to_string())
    todo!()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_fetch() {
        let data = fetch_timetable("", "").unwrap();
        println!("{:?}", data.1);
    }
}