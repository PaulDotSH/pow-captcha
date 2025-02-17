pub trait Store {
    fn store(&self, key: String) -> String;
    fn retrieve(&self, token: String) -> String;
}

/*
    Workflow

    Think of an api that will send each user an token to know which params they have so they cant be modified client side
*/