use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let bindings = bindgen::Builder::default()
        .header_contents(
            "wrapper.h",
            r#"
            #include <sasl/sasl.h>
            #include <sasl/saslplug.h>
            "#,
        )
        // Only generate bindings for the types/constants we actually use
        .allowlist_type("sasl_utils_t")
        .allowlist_type("sasl_client_plug_t")
        .allowlist_type("sasl_client_params_t")
        .allowlist_type("sasl_out_params_t")
        .allowlist_type("sasl_interact_t")
        .allowlist_type("sasl_secret_t")
        .allowlist_type("sasl_security_properties_t")
        .allowlist_type("sasl_callback_t")
        .allowlist_var("SASL_OK")
        .allowlist_var("SASL_CONTINUE")
        .allowlist_var("SASL_INTERACT")
        .allowlist_var("SASL_FAIL")
        .allowlist_var("SASL_NOMEM")
        .allowlist_var("SASL_BADPROT")
        .allowlist_var("SASL_BADPARAM")
        .allowlist_var("SASL_TRYAGAIN")
        .allowlist_var("SASL_BADVERS")
        .allowlist_var("SASL_CB_LIST_END")
        .allowlist_var("SASL_CB_AUTHNAME")
        .allowlist_var("SASL_CB_PASS")
        .allowlist_var("SASL_CU_AUTHID")
        .allowlist_var("SASL_CU_AUTHZID")
        .allowlist_var("SASL_SEC_NOANONYMOUS")
        .allowlist_var("SASL_SEC_NOPLAINTEXT")
        .allowlist_var("SASL_SEC_PASS_CREDENTIALS")
        .allowlist_var("SASL_FEAT_WANT_CLIENT_FIRST")
        .allowlist_var("SASL_FEAT_ALLOWS_PROXY")
        .allowlist_var("SASL_CLIENT_PLUG_VERSION")
        // Derive traits for convenience
        .derive_debug(true)
        .derive_default(true)
        // Emit #define constants as i32 (signed), matching SASL's int return types
        .default_macro_constant_type(bindgen::MacroTypeVariation::Signed)
        // Use core types
        .use_core()
        .generate()
        .expect("Unable to generate SASL bindings. Is libsasl2-dev installed?");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("sasl_bindings.rs"))
        .expect("Couldn't write SASL bindings");
}
