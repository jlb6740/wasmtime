mod env {

    use wasmtime::{Linker, Module, Store};

    fn pthread_create() {
        /*
                let store = Store::default();
                let mut linker = Linker::new(&store);
                linker
                    .func(
                        "env",
                        "pthread_create",
                        |x1: i32, _x2: i32, _x3: i32, _x4: i32| x1,
                    )
                    .unwrap();

                let wat = r#"
                    (module
                        (import "env" "pthread_create" (func (param i32 i32 i32 i32) (result i32)))
                    )
                "#;
                let module = Module::new(store.engine(), wat).unwrap();
                linker.instantiate(&module).unwrap();
        */
        let store = Store::default();
        let mut linker = Linker::new(&store);

        // Instantiate a small instance...
        let wat = r#"(module (func (export "pthread_create") ))"#;
        let module = Module::new(store.engine(), wat).unwrap();
        let instance = linker.instantiate(&module).unwrap();

        // ... and inform the linker that the name of this instance is
        // `instance1`. This defines the `instance1::run` name for our next
        // module to use.
        linker.instance("env", &instance).unwrap();
        /*
        let wat = r#"
            (module
                (import "env" "pthread_create" (func (param i32 i32 i32 i32) (result i32)))
                (func (export "pthread_create")

                )
            )
        "#;
        let module = Module::new(store.engine(), wat).unwrap();
        let instance = linker.instantiate(&module).unwrap();*/
    }
}
