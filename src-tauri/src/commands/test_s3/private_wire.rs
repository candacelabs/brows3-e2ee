use super::*;
use std::collections::BTreeMap;
use tokio::io::AsyncReadExt as _;

pub(super) async fn exercise_upload_list_download() {
    let bucket = format!("b3e1-{}", "1".repeat(32));
    let key = envelope::random_key().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let prefix = "confidential-folder/";
    let names = [
        "confidential-folder/payroll.csv",
        "confidential-folder/legal-notes.txt",
    ];
    let ids = names.map(|n| object_privacy::address(&key, &bucket, n).unwrap());
    let sizes = [5usize << 20, 7usize << 20];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = crate::commands::test_s3::client_for_endpoint(format!(
        "http://{}",
        listener.local_addr().unwrap()
    ));
    let physical_ids = ids.clone();
    let server = tokio::spawn(async move {
        let mut stored = BTreeMap::<String, (String, Vec<u8>)>::new();
        for _ in 0..6 {
            let (mut socket, _) =
                tokio::time::timeout(std::time::Duration::from_secs(10), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
            let mut stream = tokio::io::BufReader::new(&mut socket);
            let mut headers = Vec::new();
            use tokio::io::AsyncBufReadExt;
            loop {
                let n = stream.read_until(b'\n', &mut headers).await.unwrap();
                assert!(n > 0);
                if headers.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let headers = String::from_utf8(headers).unwrap();
            let line = headers.lines().next().unwrap().to_owned();
            let value = |key: &str| {
                headers
                    .lines()
                    .filter_map(|s| s.split_once(':'))
                    .find(|(n, _)| n.eq_ignore_ascii_case(key))
                    .map(|(_, v)| v.trim())
            };
            let length = value("content-length")
                .unwrap_or("0")
                .parse::<usize>()
                .unwrap();
            if value("expect").is_some_and(|v| v.eq_ignore_ascii_case("100-continue")) {
                stream
                    .get_mut()
                    .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                    .await
                    .unwrap();
            }
            let mut body = vec![0; length];
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                stream.read_exact(&mut body),
            )
            .await
            .unwrap()
            .unwrap();
            for marker in ["confidential-folder", "payroll.csv", "legal-notes.txt"] {
                assert!(!headers.contains(marker));
                assert!(!body.windows(marker.len()).any(|w| w == marker.as_bytes()));
            }
            let mut extra = String::new();
            let response_body;
            let response_size;
            let id = physical_ids.iter().find(|s| line.contains(s.as_str()));
            match line.split_whitespace().next().unwrap() {
                "PUT" => {
                    let id = id.unwrap();
                    let sealed = value("x-amz-meta-brows3-record-v2").unwrap().to_string();
                    assert_eq!(value("if-none-match"), Some("*"));
                    assert_eq!(length as u64, envelope::cipher_size(8 << 20));
                    assert!(stored.insert(id.clone(), (sealed, body)).is_none());
                    response_body = Vec::new();
                    response_size = 0;
                }
                "GET" if line.contains("list-type=2") => {
                    let entries = stored
                        .iter()
                        .map(|(id, (_, b))| {
                            format!(
                                "<Contents><Key>{id}</Key><Size>{}</Size></Contents>",
                                b.len()
                            )
                        })
                        .collect::<String>();
                    response_body=format!("<ListBucketResult><IsTruncated>false</IsTruncated>{entries}</ListBucketResult>").into_bytes();
                    response_size = response_body.len();
                }
                method @ ("HEAD" | "GET") => {
                    let (sealed, bytes) = stored.get(id.unwrap()).unwrap();
                    extra = format!("x-amz-meta-brows3-record-v2: {sealed}\r\n");
                    response_size = bytes.len();
                    response_body = if method == "GET" {
                        bytes.clone()
                    } else {
                        Vec::new()
                    };
                }
                _ => panic!("unexpected request"),
            }
            let response=format!("HTTP/1.1 200 OK\r\nContent-Length: {response_size}\r\nConnection: close\r\n{extra}\r\n");
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.write_all(&response_body).await.unwrap();
        }
    });
    for (i, name) in names.iter().enumerate() {
        let source = directory.path().join(format!("source-{i}"));
        std::fs::write(&source, vec![i as u8 + 1; sizes[i]]).unwrap();
        upload(&client, &bucket, name, &source, key.clone())
            .await
            .unwrap();
    }
    let page = list_private_page(&client, &bucket, prefix, None, None, &key)
        .await
        .unwrap();
    assert_eq!(
        page.objects
            .iter()
            .map(|o| (&*o.key, o.size))
            .collect::<Vec<_>>(),
        vec![(names[1], sizes[1] as i64), (names[0], sizes[0] as i64)]
    );
    let output = directory.path().join("recovered");
    download(&client, &bucket, names[1], &output, key)
        .await
        .unwrap();
    assert_eq!(std::fs::read(output).unwrap(), vec![2; sizes[1]]);
    server.await.unwrap();
}
