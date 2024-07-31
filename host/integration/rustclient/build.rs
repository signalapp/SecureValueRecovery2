fn main() {
    let protos = [
        "proto/msgs.proto",
    ];
    prost_build::compile_protos(&protos, &["proto"]).expect("Protobufs in src are valid");
    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto);
    }
}
