use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{
    nsm_exit,
    nsm_init,
    nsm_process_request,
};

use base64::{engine::general_purpose::STANDARD, Engine};

fn main() {
    let fd = nsm_init();

    if fd < 0 {
        eprintln!("Unable to open /dev/nsm");
        std::process::exit(1);
    }

    let response = nsm_process_request(
        fd,
        Request::Attestation {
            user_data: None,
            nonce: None,
            public_key: None,
        },
    );

    match response {
        Response::Attestation { document } => {
            println!(
                "{}",
                serde_json::json!({
                    "attestation_document":
                        STANDARD.encode(document)
                })
            );
        }

        Response::Error(err) => {
            eprintln!("NSM error: {:?}", err);
            std::process::exit(1);
        }

        other => {
            eprintln!("Unexpected response: {:?}", other);
            std::process::exit(1);
        }
    }

    nsm_exit(fd);
}
