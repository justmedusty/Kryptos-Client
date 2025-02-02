use std::fmt;

pub trait Encryption {
    fn initialize_context(&mut self);

    /*
        Changing all references to mutable because in some cases you might need to resize the input buffer
        if it doesn't align with a certain block size alignment
     */
    fn encrypt(&mut self, input:  &mut Vec<u8>, output : &mut Vec<u8>);
    fn decrypt(&mut self, input:  &mut Vec<u8>, output: &mut Vec<u8>);
    fn set_key(&mut self, key: &[u8]);
}

/*
 Going with dynamic dispatch over generics since I don't want to have to define
 the generic type everywhere
*/
pub struct EncryptionContext {
    /*
        Remember that dynamic dispatch results in a run time hit
        with vtable lookups, for this it is ok but it is important
        to remember that
     */
    pub context: Box<dyn Encryption>,
}
/*
    This s required since the parent struct Telnet derives the debug trait
 */
impl fmt::Debug for EncryptionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Custom debug logic, for example:
        f.debug_struct("EncryptionContext")
            .field("context", &"Encrypted Data")
            .finish()
    }
}
/*
   We can implement these as Send and Sync because we will not be accessing other threads private encryption context
   Obviously if you try to share it then it becomes an issue. This is just to silence the warnings about moving across thread
   boundaries
*/
unsafe impl Send for EncryptionContext {}
unsafe impl Sync for EncryptionContext {}
impl EncryptionContext {
    pub fn new<T: Encryption + 'static>(context: T) -> EncryptionContext {
        EncryptionContext {
            context: Box::new(context),
        }
    }
}
