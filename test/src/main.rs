use osquery::OsqueryInstance;

fn main() {
    println!("Hello, world!");
    let instance = OsqueryInstance::start().expect("failed to start embedded osquery");

    let result = instance.query("select * from apps").unwrap();

    println!("{:?}", result);
}
